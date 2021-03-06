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

// Package restorer provides restorer service
package restorer

import (
	"github.com/vdaas/vald/internal/errgroup"
	"github.com/vdaas/vald/pkg/agent/sidecar/service/storage"
)

type Option func(r *restorer) error

var (
	defaultOpts = []Option{
		WithErrGroup(errgroup.Get()),
	}
)

func WithErrGroup(eg errgroup.Group) Option {
	return func(r *restorer) error {
		if eg != nil {
			r.eg = eg
		}
		return nil
	}
}

func WithDir(dir string) Option {
	return func(r *restorer) error {
		if dir == "" {
			return nil
		}

		r.dir = dir

		return nil
	}
}

func WithBlobStorage(storage storage.Storage) Option {
	return func(r *restorer) error {
		if storage != nil {
			r.storage = storage
		}
		return nil
	}
}
