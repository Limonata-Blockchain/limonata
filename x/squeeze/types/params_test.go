package types

import "testing"

// TestParamsValidateBounds proves Validate enforces the governance safety bounds so no
// gov vote can push the squeeze fee split to economy-breaking values: BurnBps in
// [1000,5000], GrantBps in [1000,4000], and BurnBps+GrantBps (the validator take) in
// [3000,7000] (i.e. validators always keep [30%,70%]).
func TestParamsValidateBounds(t *testing.T) {
	testCases := []struct {
		name    string
		params  Params
		wantErr bool
	}{
		{
			name:    "default (20/20/60) passes",
			params:  DefaultParams(),
			wantErr: false,
		},
		{
			name:    "burn below floor (5%) fails",
			params:  Params{BurnBps: 500, GrantBps: 2000},
			wantErr: true,
		},
		{
			name:    "burn above ceiling (60%) fails",
			params:  Params{BurnBps: 6000, GrantBps: 1000},
			wantErr: true,
		},
		{
			name:    "grant below floor (5%) fails",
			params:  Params{BurnBps: 2000, GrantBps: 500},
			wantErr: true,
		},
		{
			name:    "grant above ceiling (50%) fails",
			params:  Params{BurnBps: 2000, GrantBps: 5000},
			wantErr: true,
		},
		{
			name:    "10/10/80 split fails: distribution 80% exceeds 70% ceiling",
			params:  Params{BurnBps: 1000, GrantBps: 1000},
			wantErr: true,
		},
		{
			name:    "50/40/10 split fails: distribution 10% below 30% floor",
			params:  Params{BurnBps: 5000, GrantBps: 4000},
			wantErr: true,
		},
		{
			name:    "valid non-default 30/20/50 split passes",
			params:  Params{BurnBps: 3000, GrantBps: 2000},
			wantErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.params.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("Validate() = nil, want error for %+v", tc.params)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Validate() = %v, want nil for %+v", err, tc.params)
			}
		})
	}
}
