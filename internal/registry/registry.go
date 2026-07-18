// Package registry fetches OCI image config and layer metadata directly from
// a container registry or an image tarball — no Docker daemon required.
package registry

import (
	"context"
	"fmt"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// HistoryEntry is one entry of the image config's history array, paired with
// the layer it produced (if any).
type HistoryEntry struct {
	// Index is the position in the config history array.
	Index     int
	CreatedBy string
	Comment   string
	// EmptyLayer is true for metadata-only instructions (ENV, LABEL, ...).
	EmptyLayer bool
	// DiffID is the uncompressed layer digest, empty for empty layers.
	DiffID string
	// Digest is the compressed (registry) layer digest, when known.
	Digest string
	// Size is the compressed layer size in bytes, when known.
	Size int64
}

// Image is the metadata layerblame needs from an image.
type Image struct {
	Ref     string
	Digest  string
	History []HistoryEntry
	// DiffIDs are the uncompressed layer digests in order.
	DiffIDs []string
}

// Fetch pulls config and manifest for ref from its registry. platform may be
// empty ("linux/amd64" style otherwise).
func Fetch(ctx context.Context, ref, platform string) (*Image, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("parse image reference %q: %w", ref, err)
	}
	opts := []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	}
	if platform != "" {
		p, err := v1.ParsePlatform(platform)
		if err != nil {
			return nil, fmt.Errorf("parse platform %q: %w", platform, err)
		}
		opts = append(opts, remote.WithPlatform(*p))
	}
	img, err := remote.Image(r, opts...)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", ref, err)
	}
	return fromV1(ref, img)
}

// FetchTarball reads image metadata from a docker-save style tarball, which
// lets CI analyze an image without pushing it to a registry.
func FetchTarball(path string) (*Image, error) {
	img, err := tarball.ImageFromPath(path, nil)
	if err != nil {
		return nil, fmt.Errorf("read image tarball %s: %w", path, err)
	}
	return fromV1(path, img)
}

func fromV1(ref string, img v1.Image) (*Image, error) {
	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("read image config: %w", err)
	}
	out := &Image{Ref: ref}
	if d, err := img.Digest(); err == nil {
		out.Digest = d.String()
	}
	for _, d := range cfg.RootFS.DiffIDs {
		out.DiffIDs = append(out.DiffIDs, d.String())
	}

	// Manifest layers line up with non-empty history entries; use them for
	// compressed digests and sizes when available.
	var manifestLayers []v1.Descriptor
	if m, err := img.Manifest(); err == nil {
		manifestLayers = m.Layers
	}

	layerIdx := 0
	for i, h := range cfg.History {
		e := HistoryEntry{
			Index:      i,
			CreatedBy:  h.CreatedBy,
			Comment:    h.Comment,
			EmptyLayer: h.EmptyLayer,
		}
		if !h.EmptyLayer {
			if layerIdx < len(out.DiffIDs) {
				e.DiffID = out.DiffIDs[layerIdx]
			}
			if layerIdx < len(manifestLayers) {
				e.Digest = manifestLayers[layerIdx].Digest.String()
				e.Size = manifestLayers[layerIdx].Size
			}
			layerIdx++
		}
		out.History = append(out.History, e)
	}

	// Some images ship without history; synthesize non-empty entries so
	// attribution can still bucket findings per layer.
	if len(cfg.History) == 0 {
		for i, d := range out.DiffIDs {
			e := HistoryEntry{Index: i, DiffID: d}
			if i < len(manifestLayers) {
				e.Digest = manifestLayers[i].Digest.String()
				e.Size = manifestLayers[i].Size
			}
			out.History = append(out.History, e)
		}
	}
	return out, nil
}
