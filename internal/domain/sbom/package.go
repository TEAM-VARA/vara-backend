package sbom

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ─────────────────────────────────────────
// SBOM Package (PURL 단위)
// ─────────────────────────────────────────

// SBOMPackage는 Trivy SBOM에서 추출한 단일 패키지입니다.
type SBOMPackage struct {
	ImageDigest string `json:"image_digest"`

	PURL      string `json:"purl"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`

	Arch        string   `json:"arch,omitempty"`
	SrcName     string   `json:"src_name,omitempty"`
	SrcVersion  string   `json:"src_version,omitempty"`
	LayerDigest string   `json:"layer_digest,omitempty"`
	PkgClass    string   `json:"pkg_class,omitempty"` // os-pkgs / lang-pkgs
	Target      string   `json:"target,omitempty"`
	Licenses    []string `json:"licenses,omitempty"`
}

// ─────────────────────────────────────────
// Trivy SBOM 파싱 (raw_data → []SBOMPackage)
// ─────────────────────────────────────────
//
// Trivy v0.70.0 SBOM 형식:
//
//	{
//	  "Results": [
//	    {
//	      "Target": "nginx:1.14.0 (debian 9.5)",
//	      "Class":  "os-pkgs",
//	      "Type":   "debian",
//	      "Packages": [
//	        {
//	          "Name": "adduser",
//	          "Version": "3.115",
//	          "Arch": "all",
//	          "SrcName": "adduser",
//	          "SrcVersion": "3.115",
//	          "Layer": {"DiffID": "sha256:...", "Digest": "sha256:..."},
//	          "Licenses": ["GPL-2.0-only"],
//	          "Identifier": {"PURL": "pkg:deb/debian/adduser@3.115?arch=all&distro=debian-9.5"}
//	        }
//	      ]
//	    }
//	  ]
//	}

// 내부 파싱 구조체
type trivyRaw struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target   string         `json:"Target"`
	Class    string         `json:"Class"`
	Type     string         `json:"Type"`
	Packages []trivyPackage `json:"Packages"`
}

type trivyPackage struct {
	ID         string         `json:"ID"`
	Name       string         `json:"Name"`
	Version    string         `json:"Version"`
	Arch       string         `json:"Arch"`
	SrcName    string         `json:"SrcName"`
	SrcVersion string         `json:"SrcVersion"`
	Layer      trivyLayer     `json:"Layer"`
	Licenses   []string       `json:"Licenses"`
	Identifier trivyIdentifier `json:"Identifier"`
}

type trivyLayer struct {
	Digest string `json:"Digest"`
	DiffID string `json:"DiffID"`
}

type trivyIdentifier struct {
	UID  string `json:"UID"`
	PURL string `json:"PURL"`
}

// ExtractPackages는 Trivy SBOM raw_data에서 모든 패키지를 추출합니다.
//
//	imageDigest: 어느 이미지의 SBOM인지 (sboms.image_digest)
//	rawData:     sboms.raw_data (jsonb 전체)
//
// 반환된 SBOMPackage들은 image_digest가 모두 채워져 있고, PURL이 비어있는
// 패키지는 fallback으로 'pkg:<ecosystem>/<name>@<version>' 형태로 조립됩니다.
func ExtractPackages(imageDigest string, rawData []byte) ([]SBOMPackage, error) {
	if len(rawData) == 0 {
		return nil, fmt.Errorf("empty raw_data")
	}

	var parsed trivyRaw
	if err := json.Unmarshal(rawData, &parsed); err != nil {
		return nil, fmt.Errorf("unmarshal trivy sbom: %w", err)
	}

	var out []SBOMPackage
	seen := make(map[string]bool) // 중복 PURL 제거 (같은 image 내)

	for _, result := range parsed.Results {
		ecosystem := mapTrivyTypeToEcosystem(result.Type)

		for _, pkg := range result.Packages {
			if pkg.Name == "" || pkg.Version == "" {
				continue
			}

			purl := pkg.Identifier.PURL
			if purl == "" {
				// 폴백: 'pkg:<ecosystem>/<name>@<version>'
				purl = fmt.Sprintf("pkg:%s/%s@%s", ecosystem, pkg.Name, pkg.Version)
			}

			// 같은 image 내 중복 PURL 제거
			key := imageDigest + "|" + purl
			if seen[key] {
				continue
			}
			seen[key] = true

			out = append(out, SBOMPackage{
				ImageDigest: imageDigest,
				PURL:        purl,
				Name:        pkg.Name,
				Version:     pkg.Version,
				Ecosystem:   ecosystem,
				Arch:        pkg.Arch,
				SrcName:     pkg.SrcName,
				SrcVersion:  pkg.SrcVersion,
				LayerDigest: pkg.Layer.Digest,
				PkgClass:    result.Class,
				Target:      result.Target,
				Licenses:    pkg.Licenses,
			})
		}
	}

	return out, nil
}

// mapTrivyTypeToEcosystem maps Trivy's `Type` field to PURL ecosystem string.
//
//	debian/ubuntu → deb
//	alpine        → apk
//	redhat/centos/amazon → rpm
//	npm/pnpm/yarn → npm
//	pypi/pip      → pypi
//	gomod         → golang
//	maven/jar     → maven
//	composer      → composer
//	gem/bundler   → gem
//	nuget         → nuget
func mapTrivyTypeToEcosystem(trivyType string) string {
	t := strings.ToLower(trivyType)
	switch t {
	case "debian", "ubuntu":
		return "deb"
	case "alpine":
		return "apk"
	case "redhat", "centos", "rocky", "almalinux", "fedora", "oracle", "amazon", "suse", "opensuse":
		return "rpm"
	case "npm", "pnpm", "yarn":
		return "npm"
	case "pypi", "pip", "python-pkg":
		return "pypi"
	case "gomod", "golang":
		return "golang"
	case "maven", "jar", "gradle":
		return "maven"
	case "composer", "php":
		return "composer"
	case "gem", "bundler", "ruby":
		return "gem"
	case "nuget", "dotnet":
		return "nuget"
	case "cargo", "rust":
		return "cargo"
	case "cocoapods":
		return "cocoapods"
	case "swift":
		return "swift"
	case "conan":
		return "conan"
	case "hex":
		return "hex"
	case "pub", "dart":
		return "pub"
	default:
		// 모르는 type은 그대로 (PURL 표준이 아닐 수 있지만 분류는 가능)
		if t == "" {
			return "unknown"
		}
		return t
	}
}
