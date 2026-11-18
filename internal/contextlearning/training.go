package contextlearning

import (
	"cmp"
	"math/bits"
	"reverse-artex/internal/casememory"
	"slices"
)

// Search is deterministic and bounded independently of feature cardinality.
// The exact stump sweep is O(F*N*log(N)); only retained cuts get bitsets.
const cutsPerFeature = 8
const searchBeam = 16

type fitRow struct {
	v      [FeatureCount]int
	attack bool
}

type fitCut struct {
	rule  Rule
	count casememory.QualityCounts
	mask  fitMask
}

type fitMask [8]uint64 // Inputs admit at most 512 distinct cases.

func ruleLess(a, b Rule) bool {
	if a.Feature != b.Feature {
		return a.Feature < b.Feature
	}
	if a.Threshold != b.Threshold {
		return a.Threshold < b.Threshold
	}
	return a.Above && !b.Above
}

func betterCounts(a, b casememory.QualityCounts) bool {
	return a.FalseBenign < b.FalseBenign || a.FalseBenign == b.FalseBenign && a.FalseAttack < b.FalseAttack
}

func balancedLoss(c casememory.QualityCounts) int {
	// Integer class normalization avoids changing the ranking with rounding.
	return c.FalseBenign*c.Benign + c.FalseAttack*c.Attack
}

func cutLess(a, b fitCut) bool {
	if x, y := balancedLoss(a.count), balancedLoss(b.count); x != y {
		return x < y
	}
	if a.count.FalseBenign != b.count.FalseBenign {
		return a.count.FalseBenign < b.count.FalseBenign
	}
	if a.count.FalseAttack != b.count.FalseAttack {
		return a.count.FalseAttack < b.count.FalseAttack
	}
	return ruleLess(a.rule, b.rule)
}

func fitRows(in Inputs, labels map[string]string) ([]fitRow, int, int) {
	rows := make([]fitRow, 0, len(in.Rows))
	a, b := 0, 0
	for _, row := range in.Rows {
		y := labels[row.ID]
		if y != "confirmed_attack" && y != "confirmed_benign" {
			continue
		}
		attack := y == "confirmed_attack"
		if attack {
			a++
		} else {
			b++
		}
		rows = append(rows, fitRow{row.Features, attack})
	}
	return rows, a, b
}

// sweepStumps retains the legacy threshold/direction/tie order exactly.
func sweepStumps(rows []fitRow, attack, benign int) (Model, casememory.QualityCounts, []fitCut) {
	bestModel := Model{Kind: "all_alerts_suspicious", Feature: -1}
	best := casememory.QualityCounts{Attack: attack, Benign: benign, TrueAttack: attack, FalseAttack: benign}
	pool := make([]fitCut, 0, FeatureCount*cutsPerFeature)
	ordered := make([]int, len(rows))
	for i := range ordered {
		ordered[i] = i
	}
	for feature := 0; feature < FeatureCount; feature++ {
		slices.SortStableFunc(ordered, func(a, b int) int { return cmp.Compare(rows[a].v[feature], rows[b].v[feature]) })
		var kept [cutsPerFeature]fitCut
		keptCount := 0
		belowAttack, belowBenign := 0, 0
		consider := func(threshold int) {
			for _, above := range []bool{true, false} {
				c := casememory.QualityCounts{Attack: attack, Benign: benign}
				if above {
					c.TrueAttack, c.FalseBenign = attack-belowAttack, belowAttack
					c.FalseAttack, c.TrueBenign = benign-belowBenign, belowBenign
				} else {
					c.TrueAttack, c.FalseBenign = belowAttack, attack-belowAttack
					c.FalseAttack, c.TrueBenign = belowBenign, benign-belowBenign
				}
				rule := Rule{feature, threshold, above}
				if betterCounts(c, best) {
					best = c
					bestModel = Model{Kind: "context-metadata-stump/2", Feature: feature, Threshold: threshold, Above: above}
				}
				// An OR component must cover reviewed attacks without labeling
				// every benign example suspicious. Tiny one-case rules are excluded.
				if c.TrueAttack >= 3 && c.FalseAttack < benign {
					cut := fitCut{rule: rule, count: c}
					at := keptCount
					for at > 0 && cutLess(cut, kept[at-1]) {
						at--
					}
					if at < cutsPerFeature {
						end := min(keptCount, cutsPerFeature-1)
						copy(kept[at+1:end+1], kept[at:end])
						kept[at] = cut
						keptCount = min(keptCount+1, cutsPerFeature)
					}
				}
			}
		}
		consider(0)
		for i := 0; i < len(ordered); {
			value := rows[ordered[i]].v[feature]
			for i < len(ordered) && rows[ordered[i]].v[feature] == value {
				if rows[ordered[i]].attack {
					belowAttack++
				} else {
					belowBenign++
				}
				i++
			}
			consider(value + 1)
		}
		pool = append(pool, kept[:keptCount]...)
	}
	for i := range pool {
		r := pool[i].rule
		for j, row := range rows {
			if (row.v[r.Feature] >= r.Threshold) == r.Above {
				pool[i].mask[j/64] |= uint64(1) << uint(j%64)
			}
		}
	}
	slices.SortFunc(pool, func(a, b fitCut) int {
		if ruleLess(a.rule, b.rule) {
			return -1
		}
		if ruleLess(b.rule, a.rule) {
			return 1
		}
		return 0
	})
	return bestModel, best, pool
}

type fitState struct {
	mask  fitMask
	rules [MaxRules]Rule
	used  int
	count casememory.QualityCounts
}

func stateLess(a, b fitState) bool {
	if x, y := balancedLoss(a.count), balancedLoss(b.count); x != y {
		return x < y
	}
	if a.count.FalseBenign != b.count.FalseBenign {
		return a.count.FalseBenign < b.count.FalseBenign
	}
	if a.count.FalseAttack != b.count.FalseAttack {
		return a.count.FalseAttack < b.count.FalseAttack
	}
	if a.used != b.used {
		return a.used < b.used
	}
	for i, r := range a.rules[:a.used] {
		if r != b.rules[i] {
			return ruleLess(r, b.rules[i])
		}
	}
	return false
}

func fitModel(in Inputs, labels map[string]string) (Model, casememory.QualityCounts) {
	rows, attack, benign := fitRows(in, labels)
	model, best, cuts := sweepStumps(rows, attack, benign)
	if best.FalseBenign == 0 && best.FalseAttack == 0 {
		return model, best
	}
	var attacks fitMask
	for i, row := range rows {
		if row.attack {
			attacks[i/64] |= uint64(1) << uint(i%64)
		}
	}
	beam := []fitState{{count: casememory.QualityCounts{Attack: attack, Benign: benign, FalseBenign: attack, TrueBenign: benign}}}
	for depth := 1; depth <= MaxRules; depth++ {
		next := map[fitMask]fitState{}
		for _, parent := range beam {
			for _, cut := range cuts {
				mask := parent.mask
				newAttacks, tp, fp := 0, 0, 0
				for j := range mask {
					newAttacks += bits.OnesCount64((cut.mask[j] &^ mask[j]) & attacks[j])
					mask[j] |= cut.mask[j]
					tp += bits.OnesCount64(mask[j] & attacks[j])
					fp += bits.OnesCount64(mask[j] &^ attacks[j])
				}
				if newAttacks == 0 {
					continue
				}
				rules := parent.rules
				at := parent.used
				for at > 0 && ruleLess(cut.rule, rules[at-1]) {
					rules[at] = rules[at-1]
					at--
				}
				rules[at] = cut.rule
				state := fitState{mask: mask, rules: rules, used: parent.used + 1, count: casememory.QualityCounts{Attack: attack, Benign: benign, TrueAttack: tp, FalseBenign: attack - tp, FalseAttack: fp, TrueBenign: benign - fp}}
				if old, ok := next[mask]; !ok || stateLess(state, old) {
					next[mask] = state
				}
			}
		}
		ordered := make([]fitState, 0, len(next))
		for _, state := range next {
			ordered = append(ordered, state)
		}
		slices.SortFunc(ordered, func(a, b fitState) int {
			if stateLess(a, b) {
				return -1
			}
			if stateLess(b, a) {
				return 1
			}
			return 0
		})
		for _, state := range ordered {
			if state.used >= 2 && betterCounts(state.count, best) {
				model, best = Model{Kind: "context-metadata-rules/3", Feature: -1, Rules: append([]Rule(nil), state.rules[:state.used]...)}, state.count
			}
		}
		if len(ordered) > searchBeam {
			ordered = ordered[:searchBeam]
		}
		beam = ordered
		if len(beam) == 0 || best.FalseBenign == 0 && best.FalseAttack == 0 {
			break
		}
	}
	return model, best
}
