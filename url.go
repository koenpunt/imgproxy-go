package imgproxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// ImgproxyURLData is a struct that contains the data required for generating an imgproxy URL.
type ImgproxyURLData struct {
	*Imgproxy
	Options map[string]string
}

const insecureSignature = "insecure"

var allOptions = []struct {
	long  string
	short string
}{
	{"resize", "rs"},
	{"size", "s"},
	{"resizing_type", "rt"},
	{"resizing_algorithm", "ra"},
	{"width", "w"},
	{"height", "h"},
	{"min-width", "mw"},
	{"min-height", "mh"},
	{"zoom", "z"},
	{"dpr", "dpr"},
	{"enlarge", "el"},
	{"extend", "ex"},
	{"extend_aspect_ratio", "ea"},
	{"gravity", "g"},
	{"crop", "c"},
	{"trim", "t"},
	{"padding", "p"},
	{"auto_rotate", "ar"},
	{"rotate", "ro"},
	{"background", "bg"},
	{"background_alpha", "ba"},
	{"adjust", "ad"},
	{"brightness", "br"},
	{"contrast", "co"},
	{"saturation", "sa"},
	{"blur", "bl"},
	{"sharpen", "sh"},
	{"pixelate", "px"},
	{"unsharp_masking", "um"},
	{"blur_detections", "bd"},
	{"draw_detections", "dd"},
	{"gradient", "gr"},
	{"watermark", "wm"},
	{"watermark_url", "wu"},
	{"watermark_text", "wt"},
	{"watermark_size", "ws"},
	{"watermark_rotate", "wr"},
	{"watermark_shadow", "wsh"},
	{"style", "st"},
	{"strip_metadata", "sm"},
	{"keep_copyright", "kc"},
	{"dpi", "dpi"},
	{"strip_color_profile", "scp"},
	{"enforce_thumbnail", "et"},
	{"quality", "q"},
	{"format_quality", "fq"},
	{"autoquality", "aq"},
	{"max_bytes", "mb"},
	{"jpeg_options", "jpeg_options"},
	{"png_options", "png_options"},
	{"webp_options", "webp_options"},
	{"format", "f"},
	{"page", "page"},
	{"pages", "pages"},
	{"disable_animation", "da"},
	{"video_thumbnail_second", "vts"},
	{"video_thumbnail_keyframes", "vtk"},
	{"video_thumbnail_tile", "vtt"},
	{"fallback_image_url", "fi"},
	{"skip_processing", "sp"},
	{"raw", "raw"},
	{"cachebuster", "cb"},
	{"expires", "exp"},
	{"filename", "fn"},
	{"return_attachment", "ra"},
	{"preset", "pr"},
	{"hashsum", "hs"},
	{"max_src_resolution", "msr"},
	{"max_src_file_size", "msfs"},
	{"max_animation_frames", "maf"},
	{"max_animation_frame_resolution", "mafr"},
}

// processOptionMap processes the allOptions and updates the options string and opts map.
func processOptionMap(opts []struct {
	long  string
	short string
}) map[string]string {
	var optionMap = map[string]string{}

	for _, o := range opts {
		optionMap[o.long] = o.short
	}

	return optionMap
}

// Generate generates the imgproxy URL.
func (i *ImgproxyURLData) Generate(uri string) (string, error) {
	if i.cfg.EncodePath {
		uri = base64.RawStdEncoding.EncodeToString([]byte(uri))
	} else {
		uri = "plain/" + uri
	}

	opts := i.Options

	optionMap := processOptionMap(allOptions)

	options := "/"
	for _, o := range allOptions {
		option := opts[o.long]
		if len(option) == 0 {
			option = opts[o.short]
		}
		if len(option) == 0 {
			continue
		}
		options += o.short + ":" + option + "/"
		delete(opts, o.short)
		delete(opts, o.long)
	}

	// Append remaining options in alphabetical order
	keys := make([]string, len(opts))
	j := 0
	for key := range opts {
		keys[j] = key
		j++
	}
	sort.Strings(keys)

	for _, key := range keys {
		short := optionMap[key]

		if len(short) > 0 {
			key = short
		}

		options += key + ":" + opts[key] + "/"
	}

	uriWithOptions := options + uri

	if len(i.salt) == 0 && len(i.key) == 0 {
		return i.cfg.BaseURL + insecureSignature + uriWithOptions, nil
	}

	signature, err := getSignatureHash(i.key, i.salt, i.cfg.SignatureSize, uriWithOptions)
	if err != nil {
		return "", err
	}

	return i.cfg.BaseURL + signature + uriWithOptions, nil
}

func getSignatureHash(key []byte, salt []byte, signatureSize int, payload string) (string, error) {
	signature := hmac.New(sha256.New, key)

	if _, err := signature.Write(salt); err != nil {
		return "", errors.WithStack(err)
	}

	if _, err := signature.Write([]byte(payload)); err != nil {
		return "", errors.WithStack(err)
	}

	sha := base64.RawURLEncoding.EncodeToString(signature.Sum(nil)[:signatureSize])

	return sha, nil
}

// ResizingType enum.
type ResizingType string

// ResizingType enum.
const (
	// Resizes the image while keeping aspect ratio to fit a given size.
	ResizingTypeFit = ResizingType("fit")

	// Resizes the image while keeping aspect ratio to fill a given size and crops projecting parts.
	ResizingTypeFill = ResizingType("fill")

	// The same as fill, but if the resized image is smaller than the requested size, imgproxy will crop the result to keep the requested aspect ratio.
	ResizingTypeFillDown = ResizingType("fill-down")

	// Resizes the image without keeping the aspect ratio.
	ResizingTypeForce = ResizingType("force")

	// If both source and resulting dimensions have the same orientation (portrait or landscape), imgproxy will use fill. Otherwise, it will use fit.
	ResizingTypeAuto = ResizingType("auto")
)

// Resize resizes the image.
func (i *ImgproxyURLData) Resize(resizingType ResizingType, width int, height int, enlarge bool, extend bool) *ImgproxyURLData {
	return i.SetOption("resize", fmt.Sprintf(
		"%s:%d:%d:%s:%s",
		resizingType,
		width, height,
		boolAsNumberString(enlarge),
		boolAsNumberString(extend),
	))
}

// Size sets size option.
func (i *ImgproxyURLData) Size(width int, height int, enlarge bool) *ImgproxyURLData {
	return i.SetOption("size", fmt.Sprintf(
		"%d:%d:%s",
		width, height,
		boolAsNumberString(enlarge),
	))
}

// ResizingType sets the resizing type.
func (i *ImgproxyURLData) ResizingType(resizingType ResizingType) *ImgproxyURLData {
	return i.SetOption("resizing_type", string(resizingType))
}

// Width defines the width of the resulting image.
// When set to 0, imgproxy will calculate width using the defined height and source aspect ratio.
// When set to 0 and resizing type is force, imgproxy will keep the original width.
func (i *ImgproxyURLData) Width(width int) *ImgproxyURLData {
	return i.SetOption("width", strconv.Itoa(width))
}

// Height defines the height of the resulting image.
// When set to 0, imgproxy will calculate resulting height using the defined width and source aspect ratio.
// When set to 0 and resizing type is force, imgproxy will keep the original height.
func (i *ImgproxyURLData) Height(height int) *ImgproxyURLData {
	return i.SetOption("height", strconv.Itoa(height))
}

// DPR controls the output density of your image.
func (i *ImgproxyURLData) DPR(dpr int) *ImgproxyURLData {
	if dpr > 0 {
		return i.SetOption("dpr", strconv.Itoa(dpr))
	}

	return i
}

// Enlarge enlarges the image.
func (i *ImgproxyURLData) Enlarge(enlarge int) *ImgproxyURLData {
	return i.SetOption("enlarge", strconv.Itoa(enlarge))

}

// GravitySetter interface to set and get a gravity option.
type GravitySetter interface {
	SetGravityOption(i *ImgproxyURLData) *ImgproxyURLData
	GetStringOption() string
}

// OffsetGravity holds a gravity type and offsets coordinates.
type OffsetGravity struct {
	Type    GravityEnum
	XOffset int
	YOffset int
}

// SetGravityOption sets the gravity option.
func (o OffsetGravity) SetGravityOption(i *ImgproxyURLData) *ImgproxyURLData {
	return i.SetOption("gravity", o.GetStringOption())
}

// GetStringOption gets the gravity offset value as string.
func (o OffsetGravity) GetStringOption() string {
	return fmt.Sprintf("%s:%d:%d", o.Type, o.XOffset, o.YOffset)
}

// FocusPoint holds the coordinates of the focus point.
type FocusPoint struct {
	X int64
	Y int64
}

// SetGravityOption sets gravity option.
func (f FocusPoint) SetGravityOption(i *ImgproxyURLData) *ImgproxyURLData {
	return i.SetOption("gravity", f.GetStringOption())
}

// GetStringOption gets the focus point value as string.
func (f FocusPoint) GetStringOption() string {
	return fmt.Sprintf("fp:%d:%d", f.X, f.Y)
}

// GravityEnum holds a gravity option value.
type GravityEnum string

// GravityEnum constants.
const (
	// Default gravity position.
	GravityEnumCenter = GravityEnum("ce")
	// Top edge.
	GravityEnumNorth = GravityEnum("no")
	// Bottom edge.
	GravityEnumSouth = GravityEnum("so")
	// Right edge.
	GravityEnumEast = GravityEnum("ea")
	// Left edge.
	GravityEnumWest = GravityEnum("we")
	// Top-right corner.
	GravityEnumNorthEast = GravityEnum("noea")
	// Top-left corner.
	GravityEnumNorthWest = GravityEnum("nowe")
	// Bottom-right corner.
	GravityEnumSouthEast = GravityEnum("soea")
	// Bottom-left corner.
	GravityEnumSouthWest = GravityEnum("sowe")
	// Libvips detects the most "interesting" section of the image and considers it as the center of the resulting image.
	GravityEnumSmart = GravityEnum("sm")
)

// SetGravityOption sets the gravity option.
func (g GravityEnum) SetGravityOption(i *ImgproxyURLData) *ImgproxyURLData {
	return i.SetOption("g", g.GetStringOption())
}

// GetStringOption gets the gravity value as string.
func (g GravityEnum) GetStringOption() string {
	return string(g)
}

// Gravity guides imgproxy when needs to cut some parts of the image.
func (i *ImgproxyURLData) Gravity(g GravitySetter) *ImgproxyURLData {
	return g.SetGravityOption(i)
}

// Quality redefines quality of the resulting image, as a percentage.
func (i *ImgproxyURLData) Quality(quality int) *ImgproxyURLData {
	return i.SetOption("quality", strconv.Itoa(quality))
}

// HexColor holds an hexadecimal format color.
type HexColor string

// SetBgOption sets the background option.
func (h HexColor) SetBgOption(i *ImgproxyURLData) *ImgproxyURLData {
	return i.SetOption("background", string(h))
}

// RGBColor holds an RGB color.
type RGBColor struct {
	R int
	G int
	B int
}

// SetBgOption sets the background option.
func (rgb RGBColor) SetBgOption(i *ImgproxyURLData) *ImgproxyURLData {
	return i.SetOption("background", fmt.Sprintf("%d:%d:%d", rgb.R, rgb.G, rgb.B))
}

// BackgroundSetter interface to set the background option.
type BackgroundSetter interface {
	SetBgOption(*ImgproxyURLData) *ImgproxyURLData
}

// Background fills the resulting image background with the specified color.
// RGBColor are the red, green and blue channel values of the background color (0-255).
// HexColor is a hex-coded value of the color.
// Useful when you convert an image with alpha-channel to JPEG.
func (i *ImgproxyURLData) Background(bg BackgroundSetter) *ImgproxyURLData {
	return bg.SetBgOption(i)
}

// Blur applies a gaussian blur filter to the resulting image.
// The value of sigma defines the size of the mask imgproxy will use.
func (i *ImgproxyURLData) Blur(sigma int) *ImgproxyURLData {
	return i.SetOption("blur", strconv.Itoa(sigma))
}

// Sharpen applies the sharpen filter to the resulting image.
// The value of sigma defines the size of the mask imgproxy will use.
func (i *ImgproxyURLData) Sharpen(sigma int) *ImgproxyURLData {
	return i.SetOption("sharpen", strconv.Itoa(sigma))
}

// WatermarkPosition holds a watermark position option.
type WatermarkPosition string

// WatermarkPosition constants.
const (
	// Default postion.

	WatermarkPositionCenter = WatermarkPosition("ce")
	// Top edge.

	WatermarkPositionNorth = WatermarkPosition("no")
	// Bottom edge.

	WatermarkPositionSouth = WatermarkPosition("so")
	// Right edge.

	WatermarkPositionEast = WatermarkPosition("ea")
	// Left edge.

	WatermarkPositionWest = WatermarkPosition("we")
	// Top-right corner.

	WatermarkPositionNorthEast = WatermarkPosition("noea")
	// Top-left corner.

	WatermarkPositionNorthWest = WatermarkPosition("nowe")
	// Bottom-right corner.

	WatermarkPositionSouthEast = WatermarkPosition("soea")
	// Bottom-left corner.

	WatermarkPositionSouthWest = WatermarkPosition("sowe")
	// Replicate watermark to fill the whole image.

	WatermarkPositionReplicate = WatermarkPosition("re")
)

// WatermarkOffset holds the watermark coordinates.
type WatermarkOffset struct {
	X int
	Y int
}

// Watermark places a watermark on the processed image.
func (i *ImgproxyURLData) Watermark(opacity int, position WatermarkPosition, offset *WatermarkOffset, scale int) *ImgproxyURLData {
	var offsetStr string

	if offset != nil {
		offsetStr = fmt.Sprintf(":%d:%d", offset.X, offset.Y)
	}

	return i.SetOption("watermark",
		fmt.Sprintf(
			"%d:%s%s:%d", opacity, position, offsetStr, scale,
		),
	)
}

// Preset defines a list of presets to be used by imgproxy.
func (i *ImgproxyURLData) Preset(presets ...string) *ImgproxyURLData {
	return i.SetOption("preset", strings.Join(presets, ":"))
}

// CacheBuster doesn’t affect image processing but its changing allows for bypassing the CDN, proxy server and browser cache.
// Useful when you have changed some things that are not reflected in the URL, like image quality settings, presets, or watermark data.
// It’s highly recommended to prefer the cachebuster option over a URL query string because that option can be properly signed.
func (i *ImgproxyURLData) CacheBuster(buster string) *ImgproxyURLData {
	return i.SetOption("cachebuster", buster)
}

// Format specifies the resulting image format. Alias for the extension part of the URL.
func (i *ImgproxyURLData) Format(extension string) *ImgproxyURLData {
	return i.SetOption("format", extension)
}

// Crop sets the crop option.
func (i *ImgproxyURLData) Crop(width int, height int, gravity GravitySetter) *ImgproxyURLData {
	crop := fmt.Sprintf("%d:%d", width, height)

	if gravity != nil {
		crop += ":" + gravity.GetStringOption()
	}

	return i.SetOption("crop", crop)
}

// SetOption sets an option on the URL.
func (i *ImgproxyURLData) SetOption(key, value string) *ImgproxyURLData {
	i.Options[key] = value
	return i
}
