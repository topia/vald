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
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/vdaas/vald/internal/errors"
)

func TestNew(t *testing.T) {
	type args struct {
		opts []Option
	}
	type want struct {
		c   *Config
		err error
	}
	type test struct {
		name       string
		args       args
		want       want
		beforeFunc func(args)
		checkFunc  func(want, *Config, error) error
		afterFunc  func(args)
	}
	defaultCheckFunc := func(w want, c *Config, err error) error {
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
			name: "returns cfg and nil when option is not empty",
			args: args{
				opts: []Option{
					WithCert("./testdata/dummyServer.crt"),
					WithKey("./testdata/dummyServer.key"),
					WithCa("./testdata/dummyCa.pem"),
				},
			},
			want: want{
				c: func() *Config {
					var err error
					c := &credentials{
						cfg: new(tls.Config),
					}

					c.cfg.Certificates = make([]tls.Certificate, 1)
					c.cfg.Certificates[0], err = tls.LoadX509KeyPair("./testdata/dummyServer.crt", "./testdata/dummyServer.key")
					if err != nil {
						panic(err)
					}

					pool := x509.NewCertPool()
					b, err := ioutil.ReadFile("./testdata/dummyCa.pem")
					if err != nil {
						panic(err)
					}
					if !pool.AppendCertsFromPEM(b) {
						panic("faild to add cert")
					}

					c.cfg.ClientCAs = pool
					c.cfg.ClientAuth = tls.RequireAndVerifyClientCert

					c.cfg.BuildNameToCertificate()
					return c.cfg
				}(),
				err: nil,
			},
			checkFunc: func(w want, c *tls.Config, err error) error {
				if !errors.Is(err, w.err) {
					return fmt.Errorf("got error = %v, wantErr %v", err, w.err)
				}

				if len(c.Certificates) != 1 && len(c.Certificates) != len(w.c.Certificates) {
					return errors.New("Certificates length is wrong")
				}
				if got, want := string(w.c.Certificates[0].Certificate[0]), string(c.Certificates[0].Certificate[0]); want != got {
					return errors.Errorf("Certificates[0] want: %v, but got: %v", want, got)
				}

				sl := len(c.ClientCAs.Subjects())
				if sl == 0 {
					return errors.New("subjects are empty")
				}
				if got, want := c.ClientCAs.Subjects()[sl-1], w.c.ClientCAs.Subjects()[0]; !reflect.DeepEqual(got, want) {
					return errors.Errorf("ClientCAs.Subjects want: %v, got: %v", want, got)
				}

				if got, want := c.ClientAuth, w.c.ClientAuth; want != got {
					return errors.Errorf("ClientAuth want: %v, but got: %v", want, got)
				}
				return nil
			},
		},
		{
			name: "returns nil and error when option is empty",
			args: args{},
			want: want{
				err: errors.ErrTLSCertOrKeyNotFound,
			},
		},
		{
			name: "returns nil and error when cert path is empty",
			args: args{
				opts: []Option{
					WithKey("./testdata/dummyServer.key"),
				},
			},
			want: want{
				err: errors.ErrTLSCertOrKeyNotFound,
			},
		},
		{
			name: "returns nil and error when key path is empty",
			args: args{
				opts: []Option{
					WithCert("./testdata/dummyServer.crt"),
				},
			},
			want: want{
				err: errors.ErrTLSCertOrKeyNotFound,
			},
		},
		{
			name: "returns nil and error when contents of cert file is invalid",
			args: args{
				opts: []Option{
					WithCert("./testdata/invalid.crt"),
					WithKey("./testdata/dummyServer.key"),
				},
			},
			checkFunc: func(w want, c *Config, err error) error {
				wantErr := "tls: failed to find any PEM data in certificate input"
				if err.Error() != wantErr {
					return fmt.Errorf("got error = %v, wantErr %v", err, w.err)
				}
				if !reflect.DeepEqual(c, w.c) {
					return fmt.Errorf("got = %v, want %v", c, w.c)
				}
				return nil
			},
		},
		{
			name: "returns nil and error when contents of ca file is invalid",
			args: args{
				opts: []Option{
					WithCert("./testdata/dummyServer.crt"),
					WithKey("./testdata/dummyServer.key"),
					WithCa("./testdata/invalid.pem"),
				},
			},
			want: want{
				err: errors.ErrCertificationFailed,
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
			if tt.checkFunc == nil {
				tt.checkFunc = defaultCheckFunc
			}

			got, gotErr := New(tt.args.opts...)
			if err := tt.checkFunc(tt.want, got, gotErr); err != nil {
				t.Errorf("New() error = %v", err)
				return
			}
		})
	}
}

func TestNewClientConfig(t *testing.T) {
	type args struct {
		opts []Option
	}
	type want struct {
		c   *Config
		err error
	}
	type test struct {
		name       string
		args       args
		want       want
		beforeFunc func(args)
		checkFunc  func(want, *Config, error) error
		afterFunc  func(args)
	}
	defaultCheckFunc := func(w want, c *Config, err error) error {
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
			name: "returns cfg and nil when option is empty",
			want: want{
				err: nil,
			},
			checkFunc: func(w want, c *Config, err error) error {
				if !errors.Is(err, w.err) {
					return fmt.Errorf("got error = %v, wantErr %v", err, w.err)
				}
				if c == nil {
					return errors.New("config is nil")
				}
				return nil
			},
		},
		{
			name: "returns cfg and nil when cert and key option is not empty",
			args: args{
				opts: []Option{
					WithCert("./testdata/dummyServer.crt"),
					WithKey("./testdata/dummyServer.key"),
				},
			},
			want: want{
				err: nil,
			},
			checkFunc: func(w want, c *Config, err error) error {
				if !errors.Is(err, w.err) {
					return fmt.Errorf("got error = %v, wantErr %v", err, w.err)
				}
				if c == nil {
					return errors.New("config is nil")
				}
				if len(c.Certificates) != 1 {
					return errors.Errorf("invalid certificate was set. %v", c.Certificates)
				}
				return nil
			},
		},
		{
			name: "returns nil and error when contents of ca file is invalid",
			args: args{
				opts: []Option{
					WithCa("./testdata/invalid.pem"),
				},
			},
			want: want{
				err: errors.ErrCertificationFailed,
			},
		},
		{
			name: "returns nil and error when contents of cert file is invalid",
			args: args{
				opts: []Option{
					WithCert("./testdata/invalid.crt"),
					WithKey("./testdata/dummyServer.key"),
				},
			},
			checkFunc: func(w want, c *Config, err error) error {
				wantErr := "tls: failed to find any PEM data in certificate input"
				if err.Error() != wantErr {
					return fmt.Errorf("got error = %v, wantErr = %v", err, w.err)
				}
				if c != nil {
					return errors.Errorf("config is not nil: %v", c)
				}
				return nil
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
			if tt.checkFunc == nil {
				tt.checkFunc = defaultCheckFunc
			}

			got, gotErr := NewClientConfig(tt.args.opts...)
			if err := tt.checkFunc(tt.want, got, gotErr); err != nil {
				t.Errorf("NewClientConfig() error = %v", err)
				return
			}
		})
	}
}

func TestNewX509CertPool(t *testing.T) {
	type args struct {
		path string
	}
	type want struct {
		cp  *x509.CertPool
		err error
	}
	type test struct {
		name       string
		args       args
		want       want
		beforeFunc func(args)
		checkFunc  func(want, *x509.CertPool, error) error
		afterFunc  func(args)
	}
	defaultCheckFunc := func(w want, cp *x509.CertPool, err error) error {
		if !errors.Is(err, w.err) {
			return fmt.Errorf("got error = %v, wantErr %v", err, w.err)
		}
		if !reflect.DeepEqual(cp, w.cp) {
			return fmt.Errorf("got = %v, want %v", cp, w.cp)
		}
		return nil
	}
	tests := []test{
		{
			name: "returns pool and nil when the pool exists and adds the cert into pool",
			args: args{
				path: "./testdata/dummyServer.crt",
			},
			want: want{
				cp: func() *x509.CertPool {
					pool := x509.NewCertPool()
					b, _ := ioutil.ReadFile("./testdata/dummyServer.crt")
					pool.AppendCertsFromPEM(b)
					return pool
				}(),
				err: nil,
			},
			checkFunc: func(w want, cp *x509.CertPool, err error) error {
				if err != nil {
					return errors.Errorf("err is not nil. err: %v", err)
				}
				if cp == nil {
					return errors.New("got is nil")
				}

				if len(cp.Subjects()) == 0 {
					return errors.New("cert files are empty")
				}
				l := len(cp.Subjects()) - 1
				if got, want := cp.Subjects()[l], w.cp.Subjects()[0]; !reflect.DeepEqual(got, want) {
					return errors.Errorf("not equals. want: %v, got: %v", want, got)
				}

				return nil
			},
		},
		{
			name: "returns nil and error when contents of path is invalid",
			args: args{
				path: "./testdata/invalid.pem",
			},
			want: want{
				err: errors.ErrCertificationFailed,
			},
			checkFunc: func(w want, cp *x509.CertPool, err error) error {
				if !errors.Is(err, w.err) {
					return errors.Errorf("err not equals. want: %v, but got: %v", w.err, err)
				}
				if cp == nil {
					return errors.Errorf("got is nil: %v", cp)
				}
				return nil
			},
		},
		{
			name: "returns nil and error when path dose not exist",
			args: args{
				path: "not_exist",
			},
			checkFunc: func(w want, cp *x509.CertPool, err error) error {
				if err == nil {
					return errors.New("err is nil")
				}
				if cp != nil {
					return errors.Errorf("got is not nil: %v", cp)
				}
				return nil
			},
		},
		{
			name: "returns nil and error when path is empty",
			checkFunc: func(w want, cp *x509.CertPool, err error) error {
				if err == nil {
					return errors.New("err is nil")
				}
				if cp != nil {
					return errors.Errorf("got is not nil: %v", cp)
				}
				return nil
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
			if tt.checkFunc == nil {
				tt.checkFunc = defaultCheckFunc
			}

			got, gotErr := NewX509CertPool(tt.args.path)
			if err := tt.checkFunc(tt.want, got, gotErr); err != nil {
				t.Errorf("NewX509CertPool() error = %v", err)
				return
			}
		})
	}
}