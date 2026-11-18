/** Bounded file transport for the defensive decision bridge. */
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const queueRoot = path.join(root, 'artifacts');
const maxWaitSeconds = 8;
const qwenModel = 'qwen3:4b-instruct-2507-q4_K_M';

function require(ok, message) {
    if (!ok) throw Error(message);
}

function stamp() {
    return {utc: new Date().toISOString(), wall_seconds: Date.now() / 1000};
}

const hash = bytes => createHash('sha256').update(bytes).digest('hex');

function within(base, value) {
    const relative = path.relative(base, value);
    return relative && relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative);
}

async function queuePath(value) {
    const queue = path.resolve(value);
    const base = queueRoot;
    require(within(base, queue) && path.basename(queue) === 'queue', 'owned queue required');
    const stat = await fs.lstat(queue);
    require(stat.isDirectory() && !stat.isSymbolicLink(), 'regular owned queue required');
    require(within(await fs.realpath(base), await fs.realpath(queue)), 'resolved owned queue required');
    return queue;
}

async function exists(file) {
    try {
        await fs.lstat(file);
        return true;
    } catch (error) {
        if (error.code === 'ENOENT') return false;
        throw error;
    }
}

async function read(file) {
    const stat = await fs.lstat(file);
    require(stat.isFile() && !stat.isSymbolicLink() && stat.size <= 128 * 1024, 'bounded regular transport file required');
    return fs.readFile(file);
}

// The marker is a hard link to the synced record. A fresh process can finish
// publication after a tool reset between marking and exposing the sibling.
async function publish(file, value) {
    require(!await exists(file), 'existing response cannot be overwritten or replayed');
    const temporary = file + '.pending-' + randomUUID();
    const handle = await fs.open(temporary, 'wx');
    try {
        try {
            await handle.writeFile(JSON.stringify(value));
            await handle.sync();
        } finally {
            await handle.close();
        }
        try {
            await fs.link(temporary, file + '.complete');
        } catch (error) {
            if (error.code === 'EEXIST') throw Error('existing response cannot be overwritten or replayed');
            throw error;
        }
        return await committed(file);
    } finally {
        await fs.unlink(temporary);
    }
}

async function committed(file) {
    const marker = file + '.complete';
    if (!await exists(marker)) {
        if (!await exists(file)) return null;
        require(await exists(marker), 'uncommitted transport record requires reconciliation');
    }
    const marked = await read(marker);
    if (!await exists(file)) {
        require(marked.length > 0, 'legacy completion marker has no record');
        JSON.parse(marked.toString('utf8'));
        try {
            await fs.link(marker, file);
        } catch (error) {
            if (error.code !== 'EEXIST') throw error;
        }
    }
    const raw = await read(file);
    require(!marked.length || marked.equals(raw), 'completion marker differs from its record');
    return JSON.parse(raw.toString('utf8'));
}

function prefix(queue, call) {
    return path.join(queue, 'call-' + String(call).padStart(2, '0'));
}

async function configuration(queue) {
    const config = JSON.parse((await read(path.join(queue, 'worker-configuration.json'))).toString('utf8'));
    const luna = config.model === 'gpt-6-luna' && ['max', 'low'].includes(config.reasoning_effort);
    const qwen = config.model === qwenModel && config.reasoning_effort === 'none';
    require(Object.keys(config).sort().join(',') === 'agent_id,model,reasoning_effort'
        && /^\/root\/[a-z][a-z0-9_]{0,63}$/.test(config.agent_id) && (luna || qwen), 'fixed configured worker required');
    return config;
}

async function identity(queue) {
    const config = await configuration(queue);
    const ready = await committed(path.join(queue, 'worker-ready.json'));
    require(ready && Object.keys(config).every(key => ready[key] === config[key]), 'exact committed worker identity required');
    return config;
}

async function wait(queue, call, seconds) {
    require(Number.isInteger(call) && call >= 1 && call <= 5
        && Number.isFinite(seconds) && seconds >= 0 && seconds <= maxWaitSeconds, 'bounded call/wait required');
    if (call === 5) return {status: 'DONE'};
    const stem = prefix(queue, call);
    const deadline = performance.now() + seconds * 1000;
    while (true) {
        if (await exists(path.join(queue, 'STOP.json'))) return {status: 'STOP', call};
        require(!await committed(stem + '.response.json'), 'submitted call cannot be reread');
        if (await exists(stem + '.input.txt')) break;
        if (performance.now() >= deadline) return {status: 'PENDING', call};
        await new Promise(resolve => setTimeout(resolve, 20));
    }
    const raw = await read(stem + '.input.txt');
    const receiptFile = stem + '.input-read.json';
    const receipt = await committed(receiptFile) ?? await publish(receiptFile, {
        input_sha256: hash(raw), transport_input_read: stamp(),
    });
    require(receipt.input_sha256 === hash(raw), 'current input differs from its receipt');
    return {status: 'INPUT', call, ...receipt, input: raw.toString('utf8')};
}

export async function start(value, seconds = 0) {
    const queue = await queuePath(value);
    const config = await configuration(queue);
    await publish(path.join(queue, 'worker-ready.json'), {...config, agent_ready: stamp(), transport: 'node-bounded-file/2'});
    return wait(queue, 1, seconds);
}

export async function next(value, call, seconds = 0) {
    const queue = await queuePath(value);
    await identity(queue);
    return wait(queue, call, seconds);
}

export async function resume(value, seconds = 0) {
    const queue = await queuePath(value);
    await identity(queue);
    for (let call = 1; call <= 4; call++) {
        if (!await committed(prefix(queue, call) + '.response.json')) return wait(queue, call, seconds);
    }
    return {status: 'DONE'};
}

export async function commit(value, envelope) {
    const queue = await queuePath(value);
    const config = await identity(queue);
    require(!await exists(path.join(queue, 'STOP.json')), 'stopped queue cannot commit');
    require(envelope && Object.keys(envelope).sort().join(',') === 'call,input_sha256,raw_response', 'closed response envelope required');
    const {call, input_sha256, raw_response} = envelope;
    require(Number.isInteger(call) && call >= 1 && call <= 4, 'four-call limit');
    for (let prior = 1; prior < call; prior++) {
        require(await committed(prefix(queue, prior) + '.response.json'), 'no skip of original calls');
    }
    require(typeof raw_response === 'string' && Buffer.byteLength(raw_response) > 0
        && Buffer.byteLength(raw_response) <= 8192, 'bounded original response required');
    const action = JSON.parse(raw_response);
    require(action && typeof action === 'object' && !Array.isArray(action), 'JSON action object required');
    const stem = prefix(queue, call);
    require(hash(await read(stem + '.input.txt')) === input_sha256, 'current input SHA required');
    await publish(stem + '.response.json', {
        ...config, input_sha256, raw_response, agent_phases: {response_published: stamp()},
    });
    return {status: 'COMMITTED', call, input_sha256};
}

export async function submit(value, envelope, seconds = 0) {
    const result = await commit(value, envelope);
    return next(value, result.call + 1, seconds);
}
