package edge

// protectedBuffers is allocated once per Handler and exists only when the
// caller opts in to retaining protected response storage between requests.
const protectedBufferCapacity = 32

func borrowProtectedBuffer(pool chan []byte, size int) []byte {
	if pool == nil {
		return make([]byte, size)
	}
	select {
	case storage := <-pool:
		if cap(storage) >= size {
			return storage[:size]
		}
		// Replacing a too-small buffer keeps total allocated buffers bounded by
		// the 32 admission slots, even when route body limits differ.
		clear(storage[:cap(storage)])
	default:
	}
	return make([]byte, size)
}

func returnProtectedBuffer(pool chan []byte, storage []byte) {
	if pool == nil {
		return
	}
	storage = storage[:cap(storage)]
	clear(storage)
	select {
	case pool <- storage:
	default:
	}
}
