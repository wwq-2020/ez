package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/PuerkitoBio/goquery"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/util/json"
)

var mrCmd = &cobra.Command{
	Use: "mr",
	RunE: func(cmd *cobra.Command, args []string) error {
		return mr(args)
	},
}

var (
	// mrCommitMessageReg = regexp.MustCompile(`"default_merge_commit_message":"(.*)","default_merge_commit_message_with_description"`)
	diffHeadSHAReg  = regexp.MustCompile(`"diff_head_sha":"(.*)","pipeline"`)
	csrfTokenReg    = regexp.MustCompile(`<meta name="csrf-token" content="(.*)" />`)
	sourceBranchReg = regexp.MustCompile(`"source_branch":"(.*)","source_branch_protected"`)
	targetBranchReg = regexp.MustCompile(`"target_branch":"(.*)","target_branch_sha"`)
)

type autoMRReq struct {
	SHA                       string `json:"sha"`
	CommitMessage             string `json:"commit_message"`
	MergeWhenPipelineSucceeds bool   `json:"merge_when_pipeline_succeeds"`
	ShouldRemoveSourceBranch  bool   `json:"should_remove_source_branch"`
	Squash                    bool   `json:"squash"`
	SquashCommitMessage       string `json:"squash_commit_message"`
}

func mr(args []string) error {
	src, dst, err := getBrachPair()
	if err != nil {
		return err
	}

	project, err := getProject()
	if err != nil {
		return err
	}
	userHome, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	confPath := path.Join(userHome, ".ez", "gitlab")
	data, err := ioutil.ReadFile(confPath)
	if err != nil {
		return err
	}

	conf := make(map[string]string)
	if err := json.Unmarshal(data, &conf); err != nil {
		return err
	}
	username := conf["username"]
	password := conf["password"]
	group := conf["group"]
	host := conf["host"]

	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	client := &http.Client{
		Jar: jar,
	}
	loginPageURL := fmt.Sprintf("https://%s/users/sign_in", host)
	loginPageResp, err := client.Get(loginPageURL)
	if err != nil {
		return err
	}
	defer loginPageResp.Body.Close()
	doc, err := goquery.NewDocumentFromReader(loginPageResp.Body)
	if err != nil {
		return err
	}
	var token string
	doc.Find(`div[class="active login-box tab-pane"]`).Each(func(i int, s *goquery.Selection) {
		s.Find(`input[name="authenticity_token"]`).Each(func(i int, s *goquery.Selection) {
			token, _ = s.Attr("value")
		})
	})
	values := make(url.Values)
	values.Set("username", username)
	values.Set("password", password)
	values.Set("authenticity_token", token)
	value := values.Encode()
	loginURL := fmt.Sprintf("https://%s/users/auth/ldapmain/callback", host)
	loginResp, err := client.Post(loginURL, "application/x-www-form-urlencoded", strings.NewReader(value))
	if err != nil {
		return err
	}
	defer loginResp.Body.Close()

	values = make(url.Values)
	values.Set("merge_request[source_branch]", src)
	values.Set("merge_request[target_branch]", dst)
	newMRURL := fmt.Sprintf(`https://%s/%s/%s/merge_requests/new?%s`, host, group, project, values.Encode())
	newMRResp, err := client.Get(newMRURL)
	if err != nil {
		return err
	}
	defer newMRResp.Body.Close()
	doc, err = goquery.NewDocumentFromReader(newMRResp.Body)
	if err != nil {
		return err
	}
	token = ""
	doc.Find(`input[name="authenticity_token"]`).Each(func(i int, s *goquery.Selection) {
		token, _ = s.Attr("value")
	})

	values.Set("authenticity_token", token)
	values.Set("merge_request[title]", fmt.Sprintf("merge %s to %s", src, dst))
	values.Set("merge_request[description]", "")
	values.Set("merge_request[assignee_ids][]", "0")
	values.Set("merge_request[label_ids][]", "")
	values.Set("merge_request[force_remove_source_branch]", "0")
	values.Set("merge_request[squash]", "0")
	values.Set("merge_request[lock_version]", "0")
	gotMRURL := ""
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		gotMRURL = req.URL.String()
		return http.ErrUseLastResponse
	}

	mrURL := fmt.Sprintf("https://%s/%s/%s/merge_requests", host, group, project)
	mrResp, err := client.Post(mrURL, "application/x-www-form-urlencoded", strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}
	defer mrResp.Body.Close()

	if gotMRURL == "" {
		mrsURL := fmt.Sprintf("https://%s/%s/%s/merge_requests", host, group, project)
		mrsResp, err := client.Get(mrsURL)
		if err != nil {
			return err
		}
		defer mrsResp.Body.Close()
		data, err := ioutil.ReadAll(mrsResp.Body)
		if err != nil {
			fmt.Println(gotMRURL)
			return err
		}
		reg, _ := regexp.Compile(fmt.Sprintf(`<a href="(/%s/%s/merge_requests/\d+)">`, group, project))
		matches := reg.FindStringSubmatch(string(data))
		if len(matches) == 0 {
			return errors.New("unexpected err")
		}
		var wg sync.WaitGroup
		var mr string
		var lock sync.Mutex
		wg.Add(len(matches) - 1)
		for _, match := range matches[1:] {
			go func(match string) {
				defer wg.Done()
				url := fmt.Sprintf("https://%s%s", host, match)
				resp, err := client.Get(url)
				if err != nil {
					return
				}
				defer resp.Body.Close()
				data, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					fmt.Println(gotMRURL)
					return
				}
				matches := sourceBranchReg.FindStringSubmatch(string(data))
				if len(matches) != 2 {
					return
				}
				sourceBranch := matches[1]
				matches = targetBranchReg.FindStringSubmatch(string(data))
				if len(matches) != 2 {
					return
				}
				targetBranch := matches[1]
				if sourceBranch == src && targetBranch == dst {
					lock.Lock()
					mr = url
					lock.Unlock()
				}
			}(match)
		}
		wg.Wait()
		if mr != "" {
			fmt.Println(mr)
			return nil
		}
		return errors.New("unexpected err")
	}

	mrPageResp, err := client.Get(gotMRURL)
	if err != nil {
		fmt.Println(gotMRURL)
		return err
	}
	defer mrPageResp.Body.Close()

	data, err = ioutil.ReadAll(mrPageResp.Body)
	if err != nil {
		fmt.Println(gotMRURL)
		return err
	}

	autoMRURL := gotMRURL + "/merge"
	dataStr := string(data)

	matches := diffHeadSHAReg.FindStringSubmatch(dataStr)
	if len(matches) != 2 {
		fmt.Println(gotMRURL)
		return nil
	}
	sha := matches[1]

	matches = csrfTokenReg.FindStringSubmatch(dataStr)
	if len(matches) != 2 {
		fmt.Println(gotMRURL)
		return errors.New("find no csrf token")
	}
	csrfToken := matches[1]

	autoMRReqObj := &autoMRReq{
		SHA:                       sha,
		CommitMessage:             fmt.Sprintf("merge %s to %s", src, dst),
		MergeWhenPipelineSucceeds: true,
		SquashCommitMessage:       fmt.Sprintf("merge %s to %s", src, dst),
	}
	autoMRReqData, err := json.Marshal(autoMRReqObj)
	if err != nil {
		fmt.Println(gotMRURL)
		return err
	}
	autoMRReq, err := http.NewRequest(http.MethodPost, autoMRURL, bytes.NewReader(autoMRReqData))
	if err != nil {
		fmt.Println(gotMRURL)
		return err
	}
	autoMRReq.Header.Set("Content-Type", "application/json")
	autoMRReq.Header.Set("x-csrf-token", csrfToken)
	autoMRResp, err := client.Do(autoMRReq)
	if err != nil {
		fmt.Println(gotMRURL)
		return err
	}
	defer autoMRResp.Body.Close()
	fmt.Println(gotMRURL)
	return nil
}

func getBrachPair() (string, string, error) {
	cmd := exec.Command("git", "symbolic-ref", "--short", "-q", "HEAD")
	output, err := cmd.Output()
	if err != nil {
		return "", "", err
	}
	src := strings.TrimSpace(string(output))
	dst := "master"
	switch src {
	case "master":
		dst = "pre-release"
	case "pre-release":
		dst = "release"
	case "release":
		os.Exit(0)
	default:
		dst = "master"
	}
	return src, dst, nil
}

func getProject() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Base(wd), nil
}

func init() {
	root.AddCommand(mrCmd)
}
