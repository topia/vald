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
	"crypto/tls"
	"fmt"
	"reflect"
	"testing"

	"github.com/vdaas/vald/internal/errors"
)

func TestWithCert(t *testing.T) {
	type T = credentials
	type args struct {
		cert string
	}
	type want struct {
		c   *T
		err error
	}
	type test struct {
		name       string
		args       args
		want       want
		beforeFunc (func(args))
		checkFunc  func(want, *T, error) error
		afterFunc  func(args)
	}
	defaultCheckFunc := func(w want, c *T, err error) error {
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
				c: &T{
					cert: "cert",
				},
				err: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.beforeFunc != nil {
				tt.beforeFunc(tt.args)
			}
			if tt.afterFunc != nil {
				defer tt.afterFunc(tt.args)
			}

			got := WithCert(tt.args.cert)

			o := new(T)
			gotErr := got(o)

			f := defaultCheckFunc
			if tt.checkFunc != nil {
				f = tt.checkFunc
			}

			if err := f(tt.want, o, gotErr); err != nil {
				t.Errorf("WithCert() error = %v", gotErr)
			}
		})
	}
}

func TestWithKey(t *testing.T) {
	type T = credentials
	type args struct {
		key string
	}
	type want struct {
		c   *T
		err error
	}
	type test struct {
		name       string
		args       args
		want       want
		beforeFunc (func(args))
		checkFunc  func(want, *T, error) error
		afterFunc  func(args)
	}
	defaultCheckFunc := func(w want, c *T, err error) error {
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
			name: "set success when key is not empty",
			args: args{
				key: "key",
			},
			want: want{
				c: &T{
					key: "key",
				},
				err: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.beforeFunc != nil {
				tt.beforeFunc(tt.args)
			}
			if tt.afterFunc != nil {
				defer tt.afterFunc(tt.args)
			}

			got := WithKey(tt.args.key)

			o := new(T)
			gotErr := got(o)

			f := defaultCheckFunc
			if tt.checkFunc != nil {
				f = tt.checkFunc
			}

			if err := f(tt.want, o, gotErr); err != nil {
				t.Errorf("WithKey() error = %v", gotErr)
			}
		})
	}
}

func TestWithCa(t *testing.T) {
	type T = credentials
	type args struct {
		ca string
	}
	type want struct {
		c   *T
		err error
	}
	type test struct {
		name       string
		args       args
		want       want
		beforeFunc (func(args))
		checkFunc  func(want, *T, error) error
		afterFunc  func(args)
	}
	defaultCheckFunc := func(w want, c *T, err error) error {
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
			name: "set success when ca is not empty",
			args: args{
				ca: "ca",
			},
			want: want{
				c: &T{
					ca: "ca",
				},
				err: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.beforeFunc != nil {
				tt.beforeFunc(tt.args)
			}
			if tt.afterFunc != nil {
				defer tt.afterFunc(tt.args)
			}

			got := WithCa(tt.args.ca)

			o := new(T)
			gotErr := got(o)

			f := defaultCheckFunc
			if tt.checkFunc != nil {
				f = tt.checkFunc
			}

			if err := f(tt.want, o, gotErr); err != nil {
				t.Errorf("WithCa() error = %v", gotErr)
			}
		})
	}
}

func TestWithTLSConfig(t *testing.T) {
	type T = credentials
	type args struct {
		cfg *tls.Config
	}
	type want struct {
		c   *T
		err error
	}
	type test struct {
		name       string
		args       args
		want       want
		beforeFunc (func(args))
		checkFunc  func(want, *T, error) error
		afterFunc  func(args)
	}
	defaultCheckFunc := func(w want, c *T, err error) error {
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
			name: "set success when cfg is not nil",
			args: args{
				cfg: new(tls.Config),
			},
			want: want{
				c: &T{
					cfg: new(tls.Config),
				},
				err: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.beforeFunc != nil {
				tt.beforeFunc(tt.args)
			}
			if tt.afterFunc != nil {
				defer tt.afterFunc(tt.args)
			}

			got := WithTLSConfig(tt.args.cfg)

			o := new(T)
			gotErr := got(o)

			f := defaultCheckFunc
			if tt.checkFunc != nil {
				f = tt.checkFunc
			}

			if err := f(tt.want, o, gotErr); err != nil {
				t.Errorf("WithTLSConfig() error = %v", gotErr)
			}
		})
	}
}
