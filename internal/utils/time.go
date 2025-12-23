package utils

import "time"

// GetMealTime 获取用餐时段
func GetMealTime(t time.Time) string {
	hour := t.Hour()
	switch {
	case hour >= 5 && hour < 10:
		return "breakfast"
	case hour >= 10 && hour < 14:
		return "lunch"
	case hour >= 14 && hour < 17:
		return "afternoon"
	case hour >= 17 && hour < 21:
		return "dinner"
	default:
		return "night"
	}
}

// GetSeason 获取季节
func GetSeason(t time.Time) string {
	month := t.Month()
	switch {
	case month >= 3 && month <= 5:
		return "spring"
	case month >= 6 && month <= 8:
		return "summer"
	case month >= 9 && month <= 11:
		return "autumn"
	default:
		return "winter"
	}
}

