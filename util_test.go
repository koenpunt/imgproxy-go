package imgproxy

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func Test_boolAsNumberString(t *testing.T) {
	Convey("boolAsNumberString()", t, func() {
		Convey("Returns 1 for true", func() {
			So(boolAsNumberString(true), ShouldEqual, "1")
		})
		Convey("Returns 0 for false", func() {
			So(boolAsNumberString(false), ShouldEqual, "0")
		})
	})
}

func Test_formatFloat(t *testing.T) {
	Convey("formatFloat()", t, func() {
		Convey("Returns the float as string without trailing zeros", func() {
			So(formatFloat(1.234000), ShouldEqual, "1.234")
		})

		Convey("Returns the float without decimals", func() {
			So(formatFloat(2), ShouldEqual, "2")
		})
	})
}
