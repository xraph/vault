package configmgr

import (
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// A mongo read gives an object back as bson.D in document order, which the
// bson codec does not keep stable for a map written from Go. Equality has to
// ignore key order and let int, int32 and float64 meet, or a save that
// changes nothing looks like a change.
func TestSameValue(t *testing.T) {
	cases := []struct {
		name string
		a, b any
		want bool
	}{
		{"reordered bson.D against map", bson.D{{Key: "b", Value: int32(2)}, {Key: "a", Value: int32(1)}, {Key: "c", Value: "x"}}, map[string]any{"a": 1.0, "b": 2.0, "c": "x"}, true},
		{"two bson.D in different orders", bson.D{{Key: "a", Value: 1}, {Key: "b", Value: 2}}, bson.D{{Key: "b", Value: 2}, {Key: "a", Value: 1}}, true},
		{"nested reorder", map[string]any{"o": bson.D{{Key: "y", Value: 1}, {Key: "x", Value: 2}}}, map[string]any{"o": map[string]any{"x": 2.0, "y": 1.0}}, true},
		{"bson.A against slice", bson.A{int32(1), "a"}, []any{1.0, "a"}, true},
		{"int against float64", 5, 5.0, true},
		{"int32 against int64", int32(5), int64(5), true},
		{"nil against nil", nil, nil, true},
		{"different value", map[string]any{"a": 1.0}, map[string]any{"a": 2.0}, false},
		{"slice order matters", []any{1.0, 2.0}, []any{2.0, 1.0}, false},
		{"nil against empty map", nil, map[string]any{}, false},
		{"string against number", "5", 5.0, false},
		{"unmarshalable", make(chan int), make(chan int), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameValue(tc.a, tc.b); got != tc.want {
				t.Errorf("sameValue(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}
