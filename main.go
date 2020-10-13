package main

import (
	"bufio"
	"errors"
	"fmt"
	"m3u8/tool"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

const (
	CryptMethodAES  CryptMethod = "AES-128"
	CryptMethodNONE CryptMethod = "NONE"
)

var lineParameterPattern = regexp.MustCompile(`([a-zA-Z-]+)=("[^"]+"|[^",]+)`)

type CryptMethod string

type M3u8 struct {
	Segments           []*Segment
	MasterPlaylistURIs []string
}

type Segment struct {
	URI string
	Key *Key
}

type Key struct {
	URI    string
	IV     string
	key    string
	Method CryptMethod
}

type Result struct {
	URL  *url.URL
	M3u8 *M3u8
	Keys map[*Key]string
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Panic:", r)
		}
	}()
	m3u8URL := "https://iqiyi.cdn9-okzy.com/20201011/16533_c16dc915/index.m3u8"
	result, err := fromURL(m3u8URL)
	if err != nil {
		panic(err)
	}
	storeFolder := "./temp"
	if err := os.MkdirAll(storeFolder, 0777); err != nil {
		panic(err)
	}
	var wg sync.WaitGroup
	// 防止协程启动过多，限制频率
	limitChan := make(chan byte, 20)
	// 开启协程请求
	for idx, seg := range result.M3u8.Segments {
		wg.Add(1)
		go func(i int, s *Segment) {
			defer func() {
				wg.Done()
				<-limitChan
			}()
			downTs(storeFolder, s, result, i)
		}(idx, seg)
		limitChan <- 1
	}
	wg.Wait()
	// 按 ts 文件名顺序合并文件
	// 由于是从 0 开始计算，只需要递增到 len(result.M3u8.Segments)-1 即可
	mainFile, err := os.Create(filepath.Join(storeFolder, "main.mp4"))
	if err != nil {
		panic(err)
	}
	//noinspection GoUnhandledErrorResult
	defer mainFile.Close()
	for i := 0; i < len(result.M3u8.Segments); i++ {
		bytes, err := ioutil.ReadFile(filepath.Join(storeFolder, strconv.Itoa(i)+".ts"))
		if err != nil {
			fmt.Println(err.Error())
			continue
		}
		if _, err := mainFile.Write(bytes); err != nil {
			fmt.Println(err.Error())
			continue
		}
	}
	_ = mainFile.Sync()
	fmt.Println("下载完成")
}

func downTs(storeFolder string, s *Segment, result *Result, i int) (err error) {
	// 以需要命名文件
	fullURL := tool.ResolveURL(result.URL, s.URI)
	body, err := tool.Get(fullURL)
	if err != nil {
		return downTs(storeFolder, s, result, i)
	}
	defer body.Close()
	// 创建存在 TS 数据的文件
	tsFile := filepath.Join(storeFolder, strconv.Itoa(i)+".ts")
	tsFileTmpPath := tsFile + "_tmp"
	tsFileTmp, err := os.Create(tsFileTmpPath)
	if err != nil {
		fmt.Printf("create tsFileTmp failed: %s\n", err.Error())
		return downTs(storeFolder, s, result, i)
	}
	//noinspection GoUnhandledErrorResult
	defer tsFileTmp.Close()
	bytes, err := ioutil.ReadAll(body)
	if err != nil {
		fmt.Printf("Read TS file failed: %s\n", err.Error())
		return downTs(storeFolder, s, result, i)
	}
	if s.Key != nil {
		key := result.Keys[s.Key]
		if key != "" {
			bytes, err = tool.AES128Decrypt(bytes, []byte(key), []byte(s.Key.IV))
			if err != nil {
				fmt.Printf("decryt TS failed: %s\n", err.Error())
			}
		}
	}
	syncByte := uint8(71) //0x47
	bLen := len(bytes)
	for j := 0; j < bLen; j++ {
		if bytes[j] == syncByte {
			bytes = bytes[j:]
			break
		}
	}
	if _, err := tsFileTmp.Write(bytes); err != nil {
		fmt.Printf("Save TS file failed:%s\n", err.Error())
		return downTs(storeFolder, s, result, i)
	}
	_ = tsFileTmp.Close()
	// 重命名为正式文件
	if err = os.Rename(tsFileTmpPath, tsFile); err != nil {
		fmt.Printf("Rename TS file failed: %s\n", err.Error())
		return downTs(storeFolder, s, result, i)
	}
	fmt.Printf("下载成功：%s\n", fullURL)
	return
}

func fromURL(link string) (*Result, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	link = u.String()
	body, err := tool.Get(link)
	if err != nil {
		return nil, fmt.Errorf("request m3u8 URL failed: %s", err.Error())
	}
	//noinspection GoUnhandledErrorResult
	defer body.Close()
	s := bufio.NewScanner(body)
	var lines []string
	for s.Scan() {
		lines = append(lines, s.Text())
	}
	m3u8, err := parseLines(lines)
	if err != nil {
		return nil, err
	}
	// 若为 Master playlist，则再次请求获取 Media playlist
	if m3u8.MasterPlaylistURIs != nil {
		return fromURL(tool.ResolveURL(u, m3u8.MasterPlaylistURIs[0]))
	}
	if len(m3u8.Segments) == 0 {
		return nil, errors.New("can not found any segment")
	}
	result := &Result{
		URL:  u,
		M3u8: m3u8,
		Keys: make(map[*Key]string),
	}

	// 请求解密秘钥
	for _, seg := range m3u8.Segments {
		switch {
		case seg.Key == nil || seg.Key.Method == "" || seg.Key.Method == CryptMethodNONE:
			continue
		case seg.Key.Method == CryptMethodAES:
			// 如果已经请求过了，就不在请求
			if _, ok := result.Keys[seg.Key]; ok {
				continue
			}
			keyURL := seg.Key.URI
			keyURL = tool.ResolveURL(u, keyURL)
			resp, err := tool.Get(keyURL)
			if err != nil {
				return nil, fmt.Errorf("extract key failed: %s", err.Error())
			}
			keyByte, err := ioutil.ReadAll(resp)
			_ = resp.Close()
			if err != nil {
				return nil, err
			}
			fmt.Println("decryption key: ", string(keyByte))
			result.Keys[seg.Key] = string(keyByte)
		default:
			return nil, fmt.Errorf("unknown or unsupported cryption method: %s", seg.Key.Method)
		}
	}
	return result, nil
}

func parseLines(lines []string) (*M3u8, error) {
	var (
		i       = 0
		lineLen = len(lines)
		m3u8    = &M3u8{}

		key *Key
		seg *Segment
	)
	for ; i < lineLen; i++ {
		line := strings.TrimSpace(lines[i])
		if i == 0 {
			if "#EXTM3U" != line {
				return nil, fmt.Errorf("invalid m3u8, missing #EXTM3U in line 1")
			}
			continue
		}
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, "#EXT-X-STREAM-INF:"):
			i++
			m3u8.MasterPlaylistURIs = append(m3u8.MasterPlaylistURIs, lines[i])
			continue
		case !strings.HasPrefix(line, "#"):
			seg = new(Segment)
			seg.URI = line
			m3u8.Segments = append(m3u8.Segments, seg)
			seg.Key = key
			continue
		case strings.HasPrefix(line, "#EXT-X-KEY"):
			params := parseLineParameters(line)
			if len(params) == 0 {
				return nil, fmt.Errorf("invalid EXT-X-KEY: %s, line: %d", line, i+1)
			}
			key = new(Key)
			method := CryptMethod(params["METHOD"])
			if method != "" && method != CryptMethodAES && method != CryptMethodNONE {
				return nil, fmt.Errorf("invalid EXT-X-KEY method: %s, line: %d", method, i+1)
			}
			key.Method = method
			key.URI = params["URI"]
			key.IV = params["IV"]
		default:
			continue
		}
	}
	return m3u8, nil
}

func parseLineParameters(line string) map[string]string {
	r := lineParameterPattern.FindAllStringSubmatch(line, -1)
	params := make(map[string]string)
	for _, arr := range r {
		params[arr[1]] = strings.Trim(arr[2], "\"")
	}
	return params
}