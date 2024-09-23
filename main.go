package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/katana/pkg/engine/standard"
	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"
)

// Fingerprints 结构体定义了指纹数据
type Fingerprints struct {
	Fingerprint []Fingerprint `json:"fingerprint"`
}

// Fingerprint 定义单个指纹
type Fingerprint struct {
	CMS      string   `json:"cms"`
	Method   string   `json:"method"`
	Location string   `json:"location"`
	Keyword  []string `json:"keyword"`
}

func main() {
	var urls []string
	var input1 string
	var fingerprintConcurrency int

	// 解析命令行参数
	flag.StringVar(&input1, "url", "", "The starting URL to crawl")
	flag.IntVar(&fingerprintConcurrency, "concurrency", 10, "The maximum number of concurrent requests for fingerprint checking")
	flag.Parse()

	// 如果未提供起始URL，则输出错误并退出
	if input1 == "" {
		gologger.Fatal().Msg("Please provide a starting URL using -url flag")
	}

	// 配置爬虫选项
	options := &types.Options{
		MaxDepth:               3,           // Maximum depth to crawl
		FieldScope:             "rdn",       // Crawling Scope Field
		BodyReadSize:           math.MaxInt, // Maximum response size to read
		Timeout:                10,          // Timeout is the time to wait for request in seconds
		Concurrency:            10,          // Concurrency is the number of concurrent crawling goroutines
		Parallelism:            10,          // Parallelism is the number of urls processing goroutines
		Delay:                  0,           // Delay is the delay between each crawl requests in seconds
		RateLimit:              150,         // Maximum requests to send per second
		ExtensionFilter:        []string{"html", "js", "css", "png", "ttf", "woff", "htm"},
		Silent:                 true,
		IgnoreQueryParams:      true,
		ScrapeJSResponses:      true,
		ScrapeJSLuiceResponses: true,
		XhrExtraction:          true,
		AutomaticFormFill:      true,
		Headless:               true,
		Strategy:               "depth-first", // Visit strategy (depth-first, breadth-first)
		OnResult: func(result output.Result) { // Callback function to execute for result
			AddURL(&urls, result.Request.URL)
		},
	}
	// 初始化爬虫选项配置
	crawlerOptions, err := types.NewCrawlerOptions(options)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}
	// 确保在使用完毕后关闭资源
	defer crawlerOptions.Close()
	// 初始化爬虫实例
	crawler, err := standard.New(crawlerOptions)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}
	// 确保在使用完毕后关闭爬虫实例
	defer crawler.Close()
	// 定义爬取的起始URL
	var input = input1
	// 执行爬取操作
	err = crawler.Crawl(input)
	if err != nil {
		// 日志记录非致命性的错误
		gologger.Warning().Msgf("Could not crawl %s: %s", input, err.Error())
	}

	// 去除重复的URL
	urls = DeduplicateURLs(urls)
	// 开始检查URL的指纹
	gologger.Info().Msgf("Started check urls fingerpringts ...")
	check_urls(urls, fingerprintConcurrency)
}

// AddURL 向字符串切片中添加一个新的URL。
// 该函数通过指针操作，避免了切片的复制，提高了效率。
// 参数:
//
//	urls: 指向字符串切片的指针，该切片存储URL列表。
//	url: 需要添加到urls切片中的新的URL字符串。
func AddURL(urls *[]string, url string) {
	// 将新的URL添加到切片中
	*urls = append(*urls, url)
}

// DeduplicateURLs 用于去除给定URL列表中的重复URL。
// 它只考虑URL的路径部分（即去除查询参数和锚点），如果路径唯一，则保留原URL。
// 参数:
//
//	urls - 一个字符串切片，包含待去重的URLs。
//
// 返回值:
//
//	一个字符串切片，包含去重后的URLs。
func DeduplicateURLs(urls []string) []string {
	// urlPathMap 用于记录已经遇到的URL路径，以避免重复。
	urlPathMap := make(map[string]bool)
	// uniqueURLs 用于存储去重后的URLs。
	var uniqueURLs []string

	// 遍历输入的URL列表。
	for _, url := range urls {
		// 分割URL以获取路径部分。
		parts := strings.Split(url, "/")
		// 确保分割后有至少一部分。
		if len(parts) > 0 {
			// 重新组合路径，排除查询参数和锚点等部分。
			path := strings.Join(parts[:len(parts)-1], "/")
			// 如果当前路径不在urlPathMap中，将其添加到去重后的URL列表。
			if _, exists := urlPathMap[path]; !exists {
				urlPathMap[path] = true
				uniqueURLs = append(uniqueURLs, url)
			}
		}
	}

	// 返回去重后的URL列表。
	return uniqueURLs
}

// check_urls 并发检查给定URL列表的技术信息。
// 参数:
//
//	urls: 需要检查的URL列表。
//	concurrency: 并发请求数量的限制。
func check_urls(urls []string, concurrency int) {
	// 加载指纹数据，用于后续的技术识别。
	fingerprints, err := loadFingerprints("finger.json")
	if err != nil {
		fmt.Println("Error loading fingerprints:", err)
		return
	}

	var maxConcurrency = concurrency                 // 设置最大并发度
	var wg sync.WaitGroup                            // 用于等待一组并发操作完成。
	resultCh := make(chan string, len(urls))         // 初始化一个固定容量的通道，用于接收处理结果
	semaphore := make(chan struct{}, maxConcurrency) // 信号量用于控制并发度

	// 遍历URL列表，对每个URL发起GET请求并在goroutine中处理响应。
	for _, url := range urls {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			semaphore <- struct{}{}        // 获取一个信号量
			defer func() { <-semaphore }() // 任务完成后释放信号量

			// 发起GET请求并处理可能的错误。
			resp, err := sendGetRequest(url)
			if err != nil {
				fmt.Printf("Failed to fetch %s: %v\n", url, err)
				return
			}
			body, header := extractBodyAndHeader(resp)

			// 根据响应体和头信息匹配指纹，识别网站技术栈。
			cms := matchFingerprint(fingerprints, body, header)
			resultCh <- fmt.Sprintf("%s: %s", url, cms)
		}(url)
	}

	// 等待所有goroutine完成，然后关闭结果通道。
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// 从结果通道接收并打印所有URL的技术识别结果。
	for result := range resultCh {
		fmt.Println(result)
	}
}

// sendGetRequest 发送一个 GET 请求到指定的 URL 并返回响应。
// 如果响应状态码不是 200，则返回错误。
func sendGetRequest(url string) (*http.Response, error) {
	// 创建一个自定义的 http.Transport，允许跳过 SSL/TLS 证书验证
	// 注意：仅在测试环境中使用此配置，在生产环境中应始终启用证书验证
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{},
	}

	// 使用自定义的 http.Transport 创建 http.Client 实例
	client := &http.Client{Transport: tr}

	// 使用自定义的 http.Client 发送 GET 请求
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}

	// 检查响应状态码
	if resp.StatusCode != http.StatusOK {
		// 关闭响应体以释放资源
		defer func() {
			io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}()

		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return resp, nil
}

// extractBodyAndHeader 从HTTP响应中提取并返回响应体和头信息。
// 该函数首先读取响应体的内容，然后将响应体转换为字符串形式。
// 同时，它返回响应的头信息而不关闭响应体，以便于后续可能的操作。
// 参数:
//
//	resp (*http.Response): 一个指向http.Response的指针，包含从服务器返回的响应。
//
// 返回值:
//
//	string: 响应体的内容，以字符串形式返回。
//	http.Header: 响应的头信息，未经过任何修改。
func extractBodyAndHeader(resp *http.Response) (string, http.Header) {
	// 读取响应体的内容，并以字节切片的形式返回
	bodyBytes, _ := io.ReadAll(resp.Body)

	// 确保响应体被正确关闭，以释放相关资源
	defer resp.Body.Close()

	// 将响应体的字节切片转换为字符串，并与响应的头信息一起返回
	return string(bodyBytes), resp.Header
}

// loadFingerprints 从指定的JSON文件中加载指纹信息。
// 参数:
//
//	filename: 存储指纹信息的文件路径。
//
// 返回值:
//
//	Fingerprints: 成功加载的指纹信息。
//	error: 如果发生错误，则返回错误信息，否则返回nil。
func loadFingerprints(filename string) (Fingerprints, error) {
	// 读取指定文件的内容
	data, err := os.ReadFile(filename)
	if err != nil {
		// 如果文件读取失败，返回空的Fingerprints和错误信息
		return Fingerprints{}, err
	}

	// 将读取的数据解析到fingerprints变量中
	var fingerprints Fingerprints
	err = json.Unmarshal(data, &fingerprints)
	if err != nil {
		// 如果数据解析失败，返回空的Fingerprints和错误信息
		return Fingerprints{}, err
	}

	// 返回解析成功的fingerprints信息和nil错误
	return fingerprints, nil
}

// matchFingerprint 根据提供的指纹信息匹配HTTP请求中的正文和头部以识别CMS。
//
// 参数:
// - fingerprints: 指纹信息集合，包含了多个Fingerprint结构体。
// - body: HTTP请求的正文内容。
// - header: HTTP请求的头部信息。
//
// 返回:
// - string: 匹配到的CMS名称。如果没有匹配到任何CMS，则返回空字符串。
func matchFingerprint(fingerprints Fingerprints, body string, header http.Header) string {
	// 遍历指纹列表，进行匹配尝试
	for _, fp := range fingerprints.Fingerprint {
		// 根据指纹的匹配方法来执行不同的逻辑
		switch fp.Method {
		case "keyword":
			// 使用"keyword"方法时，检查关键词是否在指定位置匹配
			if matchesKeyword(fp.Location, fp.Keyword, body, header) {
				// 如果匹配成功，则返回对应的CMS名称
				return fp.CMS
			}
		default:
			// 对于非"keyword"或其他未指定的匹配方法，直接返回空字符串表示未匹配
			return ""
		}
	}
	// 所有指纹均未匹配后，返回空字符串
	return ""
}

// matchesKeyword 检查关键词在指定位置的出现情况。
// 参数:
//
//	location - 指定关键词搜索的位置，可以是"title"、"body"或"header"。
//	keywords - 关键词列表，根据location指定的位置搜索这些关键词。
//	body - 文档的主体内容，用于"title"和"body"位置的关键词搜索。
//	header - HTTP头部信息，用于"header"位置的关键词搜索。
//
// 返回值:
//
//	如果关键词在指定位置全部出现则返回true，否则返回false。
func matchesKeyword(location string, keywords []string, body string, header http.Header) bool {
	// 根据指定的位置进行关键词搜索
	switch location {
	case "title":
		// 对于"title"位置，检查所有关键词是否都出现在正文内容中
		for _, keyword := range keywords {
			if !strings.Contains(body, keyword) {
				return false
			}
		}
		return true
	case "body":
		// 对于"body"位置，检查所有关键词是否都出现在正文内容中
		for _, keyword := range keywords {
			if !strings.Contains(body, keyword) {
				return false
			}
		}
		return true
	case "header":
		// 对于"header"位置，检查所有关键词是否出现在头部信息中
		for _, keyword := range keywords {
			for k, v := range header {
				// 检查头部键或值中是否包含关键词
				if strings.Contains(k, keyword) || strings.Contains(strings.Join(v, ","), keyword) {
					return true
				}
			}
		}
	}
	// 如果位置不是"title"、"body"或"header"，或者关键词没有在指定位置找到，返回false
	return false
}
