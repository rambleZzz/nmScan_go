package plugins

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"reflect"
	"strconv"
	"strings"
)

type Auth struct {
}

type Client struct {
	email, key          string
	baseUrl, searchPath string
	fieldList           []string
	size                int
}

type ResponseJson struct {
	Error   bool       `json:"error"`
	Mode    string     `json:"mode"`
	Page    int        `json:"page"`
	Query   string     `json:"query"`
	Results [][]string `json:"results"`
	Size    int        `json:"size"`
}

type Result struct {
	Host, Title, Ip, Domain, Port, Country string
	Province, City, Country_name, Protocol string
	Server, Banner, Isp, As_organization   string
	Header, Cert                           string
}

func (r Result) Map() map[string]string {
	t := reflect.TypeOf(r)
	v := reflect.ValueOf(r)
	m := make(map[string]string)
	for k := 0; k < t.NumField(); k++ {
		key := t.Field(k).Name
		value := v.Field(k).String()
		m[key] = value
	}
	return m
}

const (
	baseURL    = "https://fofa.info"
	searchPath = "/api/v1/search/all"
	//loginPath  = "/api/v1/info/my"
)

func FofaAuth(email string, key string) bool {
	var fofa_auth_flag bool
	url := fmt.Sprintf("https://fofa.info/api/v1/info/my?email=%s&key=%s", email, key)
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	resp, err := http.DefaultClient.Do(req)
	defer resp.Body.Close()
	if err != nil {
		log.Fatalln(err)
	}
	var m map[string]interface{}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	err = json.Unmarshal(body, &m)
	if err != nil {
		log.Println(body, err)
	}
	if m["error"] == true {
		fofa_auth_flag = false
	} else {
		fofa_auth_flag = true
	}
	return fofa_auth_flag
}

func NewFofaClient(email string, key string) *Client {
	f := &Client{
		email:      email,
		key:        key,
		baseUrl:    baseURL,
		searchPath: searchPath,
		fieldList: []string{
			"host",
			"title",
			"banner",
			"header",
			"ip", "domain", "port", "country", "province",
			"city", "country_name",
			"server",
			"protocol",
			"cert", "isp", "as_organization",
		},
	}
	return f
}

func (f *Client) SetSize(i int) {
	f.size = i
}

func (f *Client) Search(keyword string) (int, []Result) {
	url := f.baseUrl + f.searchPath
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	q := req.URL.Query()
	q.Add("qbase64", keyword)
	q.Add("email", f.email)
	q.Add("key", f.key)
	q.Add("page", "1")
	q.Add("fields", strings.Join(f.fieldList, ","))
	q.Add("size", strconv.Itoa(f.size))
	q.Add("full", "false")
	req.URL.RawQuery = q.Encode()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Println(err)
		return 0, nil
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		return 0, nil
	}
	var responseJson ResponseJson
	if err = json.Unmarshal(body, &responseJson); err != nil {
		log.Println(body, err)
		return 0, nil
	}
	r := f.makeResult(responseJson)
	return responseJson.Size, r
}

func (f *Client) makeResult(responseJson ResponseJson) (results []Result) {
	for _, row := range responseJson.Results {
		var result Result
		m := reflect.ValueOf(&result).Elem()
		for index, f := range f.fieldList {
			//首字母大写
			f = strings.ToUpper(f[:1]) + f[1:]
			m.FieldByName(f).SetString(row[index])
		}
		results = append(results, result)
	}
	return results
}
