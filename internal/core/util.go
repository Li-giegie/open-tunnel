package core

func Default[T ~string | ~int | ~int64](a T, defaultValue T) T {
	var zero T
	if zero == a {
		return defaultValue
	}
	return a
}
