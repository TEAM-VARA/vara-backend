package service

import (
	"reflect"
	"testing"
)

func TestChoke_Tree(t *testing.T) {
	edges := []BlastEdge{
		{SourceUID: "A", TargetUID: "B"},
		{SourceUID: "B", TargetUID: "C"},
		{SourceUID: "B", TargetUID: "D"},
		{SourceUID: "A", TargetUID: "E"},
	}
	got := ComputeChokeScores(edges, "A")
	want := map[string]int{"B": 3, "C": 1, "D": 1, "E": 1}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tree: got %v want %v", got, want)
	}
}

func TestChoke_RedundantPath(t *testing.T) {
	edges := []BlastEdge{
		{SourceUID: "A", TargetUID: "B"},
		{SourceUID: "B", TargetUID: "C"},
		{SourceUID: "A", TargetUID: "C"}, // 우회로
		{SourceUID: "B", TargetUID: "D"},
	}
	got := ComputeChokeScores(edges, "A")
	want := map[string]int{"B": 2, "C": 1, "D": 1}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("redundant: got %v want %v", got, want)
	}
}

func TestChoke_Chain(t *testing.T) {
	edges := []BlastEdge{
		{SourceUID: "A", TargetUID: "B"},
		{SourceUID: "B", TargetUID: "C"},
		{SourceUID: "C", TargetUID: "D"},
	}
	got := ComputeChokeScores(edges, "A")
	want := map[string]int{"B": 3, "C": 2, "D": 1}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("chain: got %v want %v", got, want)
	}
}

func TestChoke_Cycle(t *testing.T) {
	edges := []BlastEdge{
		{SourceUID: "A", TargetUID: "B"},
		{SourceUID: "B", TargetUID: "C"},
		{SourceUID: "C", TargetUID: "B"}, // 사이클
	}
	got := ComputeChokeScores(edges, "A")
	want := map[string]int{"B": 2, "C": 1}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cycle: got %v want %v", got, want)
	}
}

func TestChoke_NoEdges(t *testing.T) {
	got := ComputeChokeScores(nil, "A")
	if len(got) != 0 {
		t.Fatalf("no-edges: got %v want empty", got)
	}
}

func TestChoke_SelfLoopIgnored(t *testing.T) {
	edges := []BlastEdge{
		{SourceUID: "A", TargetUID: "A"},
		{SourceUID: "A", TargetUID: "B"},
	}
	got := ComputeChokeScores(edges, "A")
	want := map[string]int{"B": 1}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("self-loop: got %v want %v", got, want)
	}
}
