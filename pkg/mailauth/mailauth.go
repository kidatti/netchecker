package mailauth

import (
	"sort"
	"strings"
	"sync"

	"netchecker/pkg/dig"
)

type Result struct {
	Domain string     `json:"domain"`
	SPF    SPFResult  `json:"spf"`
	DKIM   DKIMResult `json:"dkim"`
	DMARC  DMARCResult `json:"dmarc"`
	BIMI   BIMIResult `json:"bimi"`
}

type SPFResult struct {
	Found  bool              `json:"found"`
	Raw    string            `json:"raw,omitempty"`
	Parsed map[string]string `json:"parsed,omitempty"`
	Error  string            `json:"error,omitempty"`
}

type DKIMResult struct {
	Selectors []DKIMSelector `json:"selectors"`
}

type DKIMSelector struct {
	Selector string `json:"selector"`
	Found    bool   `json:"found"`
	Raw      string `json:"raw,omitempty"`
	Error    string `json:"error,omitempty"`
}

type DMARCResult struct {
	Found  bool              `json:"found"`
	Raw    string            `json:"raw,omitempty"`
	Parsed map[string]string `json:"parsed,omitempty"`
	Error  string            `json:"error,omitempty"`
}

type BIMIResult struct {
	Found  bool              `json:"found"`
	Raw    string            `json:"raw,omitempty"`
	Parsed map[string]string `json:"parsed,omitempty"`
	Error  string            `json:"error,omitempty"`
}

var commonDKIMSelectors = []string{
	"default", "google", "selector1", "selector2",
	"k1", "k2", "k3", "s1", "s2",
	"dkim", "mail", "smtp", "email",
	"mandrill", "everlytickey1", "everlytickey2",
	"mxvault", "amazonses",
}

func Check(domain, server string) Result {
	r := Result{Domain: domain}
	r.SPF = checkSPF(domain, server)
	r.DKIM = checkDKIM(domain, server)
	r.DMARC = checkDMARC(domain, server)
	r.BIMI = checkBIMI(domain, server)
	return r
}

func checkSPF(domain, server string) SPFResult {
	res := dig.Query(domain, "TXT", server)
	if res.Error != "" {
		return SPFResult{Error: res.Error}
	}

	for _, rec := range res.Answer {
		if rec.Type == "TXT" && strings.HasPrefix(rec.Value, "v=spf1") {
			return SPFResult{
				Found:  true,
				Raw:    rec.Value,
				Parsed: parseSPF(rec.Value),
			}
		}
	}
	return SPFResult{}
}

func checkDKIM(domain, server string) DKIMResult {
	type indexedResult struct {
		idx int
		ds  DKIMSelector
		hit bool // whether to include in results
	}

	ch := make(chan indexedResult, len(commonDKIMSelectors))
	var wg sync.WaitGroup
	for i, sel := range commonDKIMSelectors {
		wg.Add(1)
		go func(i int, sel string) {
			defer wg.Done()
			qname := sel + "._domainkey." + domain
			res := dig.Query(qname, "TXT", server)
			ds := DKIMSelector{Selector: sel}
			if res.Error != "" {
				ds.Error = res.Error
				ch <- indexedResult{idx: i, ds: ds, hit: true}
				return
			}
			for _, rec := range res.Answer {
				if rec.Type == "TXT" && strings.Contains(rec.Value, "v=DKIM1") {
					ds.Found = true
					ds.Raw = rec.Value
					break
				}
			}
			ch <- indexedResult{idx: i, ds: ds, hit: ds.Found}
		}(i, sel)
	}
	wg.Wait()
	close(ch)

	var results []indexedResult
	for r := range ch {
		if r.hit {
			results = append(results, r)
		}
	}
	sort.Slice(results, func(i, j int) bool { return results[i].idx < results[j].idx })

	selectors := make([]DKIMSelector, 0, len(results))
	for _, r := range results {
		selectors = append(selectors, r.ds)
	}
	return DKIMResult{Selectors: selectors}
}

func checkDMARC(domain, server string) DMARCResult {
	qname := "_dmarc." + domain
	res := dig.Query(qname, "TXT", server)
	if res.Error != "" {
		return DMARCResult{Error: res.Error}
	}

	for _, rec := range res.Answer {
		if rec.Type == "TXT" && strings.HasPrefix(rec.Value, "v=DMARC1") {
			return DMARCResult{
				Found:  true,
				Raw:    rec.Value,
				Parsed: parseTags(rec.Value),
			}
		}
	}
	return DMARCResult{}
}

func checkBIMI(domain, server string) BIMIResult {
	qname := "default._bimi." + domain
	res := dig.Query(qname, "TXT", server)
	if res.Error != "" {
		return BIMIResult{Error: res.Error}
	}

	for _, rec := range res.Answer {
		if rec.Type == "TXT" && strings.HasPrefix(rec.Value, "v=BIMI1") {
			return BIMIResult{
				Found:  true,
				Raw:    rec.Value,
				Parsed: parseTags(rec.Value),
			}
		}
	}
	return BIMIResult{}
}

func parseSPF(raw string) map[string]string {
	m := map[string]string{}
	parts := strings.Fields(raw)
	var mechanisms []string
	for _, p := range parts {
		if p == "v=spf1" {
			m["version"] = "spf1"
			continue
		}
		if strings.HasPrefix(p, "redirect=") {
			m["redirect"] = strings.TrimPrefix(p, "redirect=")
			continue
		}
		mechanisms = append(mechanisms, p)
	}
	if len(mechanisms) > 0 {
		m["mechanisms"] = strings.Join(mechanisms, " ")
	}
	return m
}

func parseTags(raw string) map[string]string {
	m := map[string]string{}
	parts := strings.Split(raw, ";")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		idx := strings.Index(p, "=")
		if idx < 0 {
			m[p] = ""
			continue
		}
		m[strings.TrimSpace(p[:idx])] = strings.TrimSpace(p[idx+1:])
	}
	return m
}
