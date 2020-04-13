//
// Copyright (C) 2019-2020 Vdaas.org Vald team ( kpango, rinx, kmrmt )
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

// Package tls provides implementation of Go API for tls certificate provider
package tls

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/vdaas/vald/internal/errors"
)

func TestWithCert(t *testing.T) {
	type args struct {
		cert string
	}
	type want struct {
		c   *credentials
		err error
	}
	type test struct {
		name      string
		args      args
		want      want
		checkFunc func(want, *credentials, error) error
	}
	defaultCheckFunc := func(w want, c *credentials, err error) error {
		if !errors.Is(err, w.err) {
			return fmt.Errorf("got error = %v, wantErr %v", err, w.err)
		}
		if !reflect.DeepEqual(c, w.c) {
			return fmt.Errorf("got = %v, want %v", c, w.c)
		}
		return nil
	}
	tests := []test{
		{
			name: "set cert success",
			args: args{
				cert: "cert",
			},
			want: want{
				c: &credentials{
					cert: "cert",
				},
				err: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WithCert(tt.args.cert)

			c := &credentials{}
			gotErr := got(c)

			f := defaultCheckFunc
			if tt.checkFunc != nil {
				f = tt.checkFunc
			}

			if err := f(tt.want, c, gotErr); err != nil {
				t.Errorf("WithCert() error = %v", gotErr)
			}
		})
	}
}
