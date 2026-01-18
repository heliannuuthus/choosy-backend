package amap

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"zwei-backend/internal/config"
)

// Client 高德地图客户端
type Client struct {
	apiKey       string
	weatherCache map[string]*cachedWeather
	mu           sync.RWMutex
}

type cachedWeather struct {
	data      *Weather
	expiresAt time.Time
}

// Location 位置信息
type Location struct {
	Province string
	City     string
	District string
	Adcode   string
}

// Weather 天气信息
type Weather struct {
	Temperature float64
	Humidity    int
	Weather     string
}

var (
	client     *Client
	clientOnce sync.Once
)

// GetClient 获取高德客户端单例
func GetClient() *Client {
	clientOnce.Do(func() {
		client = &Client{
			apiKey:       config.GetString("amap.api-key"),
			weatherCache: make(map[string]*cachedWeather),
		}
	})
	return client
}

// GetLocation 逆地理编码
func (c *Client) GetLocation(lat, lng float64) (*Location, error) {
	if c.apiKey == "" {
		return nil, fmt.Errorf("未配置 amap.api-key")
	}

	url := fmt.Sprintf("https://restapi.amap.com/v3/geocode/regeo?location=%.6f,%.6f&key=%s", lng, lat, c.apiKey)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("请求高德 API 失败: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Status    string `json:"status"`
		Info      string `json:"info"`
		Infocode  string `json:"infocode"`
		Regeocode struct {
			AddressComponent struct {
				Province string `json:"province"`
				City     any    `json:"city"`
				District string `json:"district"`
				Adcode   string `json:"adcode"`
			} `json:"addressComponent"`
		} `json:"regeocode"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("解析高德响应失败: %w", err)
	}

	if result.Status != "1" {
		return nil, fmt.Errorf("高德 API 错误: %s (code: %s)", result.Info, result.Infocode)
	}

	addr := result.Regeocode.AddressComponent
	city := ""
	if v, ok := addr.City.(string); ok {
		city = v
	}
	if city == "" {
		city = addr.Province
	}

	return &Location{
		Province: addr.Province,
		City:     city,
		District: addr.District,
		Adcode:   addr.Adcode,
	}, nil
}

// GetWeatherByAdcode 根据 adcode 获取天气
func (c *Client) GetWeatherByAdcode(adcode string) (*Weather, error) {
	if c.apiKey == "" {
		return nil, fmt.Errorf("未配置 amap.api-key")
	}

	url := fmt.Sprintf("https://restapi.amap.com/v3/weather/weatherInfo?city=%s&key=%s&extensions=base", adcode, c.apiKey)

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Status string `json:"status"`
		Lives  []struct {
			Temperature string `json:"temperature"`
			Humidity    string `json:"humidity"`
			Weather     string `json:"weather"`
		} `json:"lives"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if result.Status != "1" || len(result.Lives) == 0 {
		return nil, fmt.Errorf("获取天气失败")
	}

	live := result.Lives[0]
	var temp float64
	var humidity int
	_, _ = fmt.Sscanf(live.Temperature, "%f", &temp)
	_, _ = fmt.Sscanf(live.Humidity, "%d", &humidity)

	return &Weather{
		Temperature: temp,
		Humidity:    humidity,
		Weather:     live.Weather,
	}, nil
}

// GetWeather 根据经纬度获取天气（带缓存）
func (c *Client) GetWeather(lat, lng float64) (*Weather, error) {
	cacheKey := fmt.Sprintf("%.1f,%.1f", lat, lng)

	c.mu.RLock()
	if cached, ok := c.weatherCache[cacheKey]; ok && time.Now().Before(cached.expiresAt) {
		c.mu.RUnlock()
		return cached.data, nil
	}
	c.mu.RUnlock()

	location, err := c.GetLocation(lat, lng)
	if err != nil {
		return nil, err
	}

	weather, err := c.GetWeatherByAdcode(location.Adcode)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.weatherCache[cacheKey] = &cachedWeather{
		data:      weather,
		expiresAt: time.Now().Add(30 * time.Minute),
	}
	c.mu.Unlock()

	return weather, nil
}
