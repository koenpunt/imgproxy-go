package imgproxy

import "strconv"

func boolAsNumberString(i bool) string {
	if i {
		return "1"
	}

	return "0"
}

func formatFloat(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}
