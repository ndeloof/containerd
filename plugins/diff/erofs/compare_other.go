//go:build !linux

/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package erofs

import (
	"context"
	"fmt"
	"io"
	iofs "io/fs"
	"os"
	"path/filepath"

	cfs "github.com/containerd/continuity/fs"
	"github.com/containerd/errdefs"
	"github.com/containerd/log"
	goerofs "github.com/erofs/go-erofs"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/diff"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/internal/erofsutils"
	"github.com/containerd/containerd/v2/pkg/archive"
	"github.com/containerd/containerd/v2/pkg/archive/compression"
	"github.com/containerd/containerd/v2/pkg/epoch"
	"github.com/containerd/containerd/v2/pkg/labels"
)

// writeDiff generates the diff tar stream by extracting lower EROFS layers to a
// temporary directory using go-erofs and then computing the diff against upperRoot.
func writeDiff(ctx context.Context, w io.Writer, lower []mount.Mount, upperRoot string) error {
	tempDir, err := os.MkdirTemp("", "erofs-lower-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir for lower: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// Collect EROFS blob paths from lower mounts.
	// The snapshotter places individual EROFS mounts in ParentID order
	// (index 0 = most recent parent, last = oldest ancestor), followed
	// by an optional overlay mount. Apply oldest-first so newer layers
	// overwrite older ones when building the merged lower.
	var blobs []string
	for _, mnt := range lower {
		if mnt.Type == "erofs" {
			blobs = append(blobs, mnt.Source)
		}
	}
	for i := len(blobs) - 1; i >= 0; i-- {
		if err := extractEROFSToDir(blobs[i], tempDir); err != nil {
			return fmt.Errorf("failed to extract lower EROFS layer %s: %w", blobs[i], err)
		}
	}

	cw := archive.NewChangeWriter(w, upperRoot)
	if err := cfs.DiffDirChanges(ctx, tempDir, upperRoot, cfs.DiffSourceOverlayFS, cw.HandleChange); err != nil {
		return fmt.Errorf("failed to create diff tar stream: %w", err)
	}
	return cw.Close()
}

// extractEROFSToDir extracts the contents of an EROFS image into destDir,
// applying overlayfs whiteout semantics so that multiple layers can be
// merged by calling this function repeatedly (oldest layer first).
//
// mkfs.erofs --aufs converts AUFS-style whiteout files from the input tar into
// overlayfs-native metadata in the resulting EROFS image:
//   - deleted entries → character device with device number 0:0 (Rdev == 0)
//   - opaque directories → directory with xattr trusted.overlay.opaque = "y"
func extractEROFSToDir(blobPath, destDir string) error {
	f, err := os.Open(blobPath)
	if err != nil {
		return fmt.Errorf("open EROFS blob: %w", err)
	}
	defer f.Close()

	erofsFS, err := goerofs.EroFS(f)
	if err != nil {
		return fmt.Errorf("read EROFS image %s: %w", blobPath, err)
	}

	return iofs.WalkDir(erofsFS, ".", func(path string, d iofs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == "." {
			return nil
		}

		// filepath.FromSlash converts the forward-slash paths produced by
		// io/fs.WalkDir into the OS-native separator (a no-op on macOS).
		destPath := filepath.Join(destDir, filepath.FromSlash(path))

		info, err := d.Info()
		if err != nil {
			return err
		}
		mode := info.Mode()
		stat, _ := info.Sys().(*goerofs.Stat)

		// Overlayfs whiteout: a character device with device number 0:0
		// marks this path as deleted in the merged lower stack.
		if mode&iofs.ModeCharDevice != 0 && stat != nil && stat.Rdev == 0 {
			if err := os.RemoveAll(destPath); err != nil && !os.IsNotExist(err) {
				return err
			}
			return nil
		}

		switch {
		case mode.IsDir():
			// Overlayfs opaque directory: all lower-layer content for this
			// directory is hidden, so remove it before recreating.
			if stat != nil && stat.Xattrs["trusted.overlay.opaque"] == "y" {
				if err := os.RemoveAll(destPath); err != nil && !os.IsNotExist(err) {
					return err
				}
			} else if fi, serr := os.Lstat(destPath); serr == nil && !fi.IsDir() {
				// A non-dir (file/symlink) from a lower layer is being
				// replaced by a directory; remove it first.
				if err := os.Remove(destPath); err != nil {
					return err
				}
			}
			return os.MkdirAll(destPath, mode.Perm())

		case mode&iofs.ModeSymlink != 0:
			// The symlink target is stored as the file's data in EROFS.
			sf, err := erofsFS.Open(path)
			if err != nil {
				return fmt.Errorf("open symlink %s: %w", path, err)
			}
			target, err := io.ReadAll(sf)
			sf.Close()
			if err != nil {
				return fmt.Errorf("read symlink target %s: %w", path, err)
			}
			os.Remove(destPath) // replace any existing entry
			return os.Symlink(string(target), destPath)

		case mode&iofs.ModeType == 0:
			// Regular file.
			os.Remove(destPath) // replace any existing entry
			dst, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode.Perm())
			if err != nil {
				return fmt.Errorf("create file %s: %w", destPath, err)
			}
			src, err := erofsFS.Open(path)
			if err != nil {
				dst.Close()
				return fmt.Errorf("open EROFS file %s: %w", path, err)
			}
			_, copyErr := io.Copy(dst, src)
			src.Close()
			dst.Close()
			return copyErr

		default:
			// Skip non-whiteout device nodes, named pipes, sockets, etc. —
			// these cannot be created on non-Linux hosts without elevated
			// privileges and are not meaningful for diff generation.
			return nil
		}
	})
}

// Compare creates a diff between the given mounts and uploads the result
// to the content store.
func (s erofsDiff) Compare(ctx context.Context, lower, upper []mount.Mount, opts ...diff.Opt) (d ocispec.Descriptor, err error) {
	layer, err := erofsutils.MountsToLayer(upper)
	if err != nil {
		return emptyDesc, fmt.Errorf("unsupported layer for erofsDiff Compare method: %w", err)
	}

	var config diff.Config
	for _, opt := range opts {
		if err := opt(&config); err != nil {
			return emptyDesc, err
		}
	}
	if tm := epoch.FromContext(ctx); tm != nil && config.SourceDateEpoch == nil {
		config.SourceDateEpoch = tm
	}

	if config.MediaType == "" {
		config.MediaType = ocispec.MediaTypeImageLayerGzip
	}

	var compressionType compression.Compression
	switch config.MediaType {
	case ocispec.MediaTypeImageLayer:
		compressionType = compression.Uncompressed
	case ocispec.MediaTypeImageLayerGzip:
		compressionType = compression.Gzip
	case ocispec.MediaTypeImageLayerZstd:
		compressionType = compression.Zstd
	default:
		return emptyDesc, fmt.Errorf("unsupported diff media type: %v: %w", config.MediaType, errdefs.ErrNotImplemented)
	}

	var newReference bool
	if config.Reference == "" {
		newReference = true
		config.Reference = uniqueRef()
	}

	cw, err := s.store.Writer(ctx,
		content.WithRef(config.Reference),
		content.WithDescriptor(ocispec.Descriptor{
			MediaType: config.MediaType, // most contentstore implementations just ignore this
		}))
	if err != nil {
		return emptyDesc, fmt.Errorf("failed to open writer: %w", err)
	}

	// errOpen is set when an error occurs while the content writer has not been
	// committed or closed yet to force a cleanup
	var errOpen error
	defer func() {
		if errOpen != nil {
			cw.Close()
			if newReference {
				if abortErr := s.store.Abort(ctx, config.Reference); abortErr != nil {
					log.G(ctx).WithError(abortErr).WithField("ref", config.Reference).Warnf("failed to delete diff upload")
				}
			}
		}
	}()
	if !newReference {
		if errOpen = cw.Truncate(0); errOpen != nil {
			return emptyDesc, errOpen
		}
	}

	upperRoot := filepath.Join(layer, "fs")
	if compressionType != compression.Uncompressed {
		dgstr := digest.SHA256.Digester()
		var compressed io.WriteCloser
		if config.Compressor != nil {
			compressed, errOpen = config.Compressor(cw, config.MediaType)
			if errOpen != nil {
				return emptyDesc, fmt.Errorf("failed to get compressed stream: %w", errOpen)
			}
		} else {
			compressed, errOpen = compression.CompressStream(cw, compressionType)
			if errOpen != nil {
				return emptyDesc, fmt.Errorf("failed to get compressed stream: %w", errOpen)
			}
		}
		errOpen = writeDiff(ctx, io.MultiWriter(compressed, dgstr.Hash()), lower, upperRoot)
		compressed.Close()
		if errOpen != nil {
			return emptyDesc, fmt.Errorf("failed to write compressed diff: %w", errOpen)
		}

		if config.Labels == nil {
			config.Labels = map[string]string{}
		}
		config.Labels[labels.LabelUncompressed] = dgstr.Digest().String()
	} else {
		err := writeDiff(ctx, cw, lower, upperRoot)
		if err != nil {
			return emptyDesc, fmt.Errorf("failed to create diff tar stream: %w", err)
		}
	}

	var commitopts []content.Opt
	if config.Labels != nil {
		commitopts = append(commitopts, content.WithLabels(config.Labels))
	}

	dgst := cw.Digest()
	if errOpen = cw.Commit(ctx, 0, dgst, commitopts...); errOpen != nil {
		if !errdefs.IsAlreadyExists(errOpen) {
			return emptyDesc, fmt.Errorf("failed to commit: %w", errOpen)
		}
		errOpen = nil
	}

	info, err := s.store.Info(ctx, dgst)
	if err != nil {
		return emptyDesc, fmt.Errorf("failed to get info from content store: %w", err)
	}
	if info.Labels == nil {
		info.Labels = make(map[string]string)
	}
	// Set "containerd.io/uncompressed" label if digest already existed without label
	if _, ok := info.Labels[labels.LabelUncompressed]; !ok {
		info.Labels[labels.LabelUncompressed] = config.Labels[labels.LabelUncompressed]
		if _, err := s.store.Update(ctx, info, "labels."+labels.LabelUncompressed); err != nil {
			return emptyDesc, fmt.Errorf("error setting uncompressed label: %w", err)
		}
	}

	return ocispec.Descriptor{
		MediaType: config.MediaType,
		Size:      info.Size,
		Digest:    info.Digest,
	}, nil
}
