package csrf

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOriginOKTrue(t *testing.T) {
	testUrl, _ := url.Parse("https://am-lich.com")
	assert.True(t, originOK(testUrl))
}

func TestOriginOKFalse(t *testing.T) {
	testUrl := &url.URL{}
	assert.False(t, originOK(testUrl))

	testUrl = &url.URL{Scheme: "https"}
	assert.False(t, originOK(testUrl))
}

func TestSameOriginTrue(t *testing.T) {
	testUrl1, _ := url.Parse("https://am-lich.com")
	testUrl2, _ := url.Parse("https://am-lich.com")
	assert.True(t, sameOrigin(testUrl1, testUrl2))
}

func TestSameOriginFalse(t *testing.T) {
	testUrl1, _ := url.Parse("https://am-lich.com")
	testUrl2, _ := url.Parse("https://vnmedia.se")
	assert.False(t, sameOrigin(testUrl1, testUrl2))
}

func TestSameOriginFalseBNotOk(t *testing.T) {
	testUrl1, _ := url.Parse("https://am-lich.com")
	testUrl2 := &url.URL{Scheme: "https"}
	assert.False(t, sameOrigin(testUrl1, testUrl2))
}

func TestSameOriginFalseANotOk(t *testing.T) {
	testUrl1 := &url.URL{Scheme: "https"}
	testUrl2, _ := url.Parse("https://am-lich.com")
	assert.False(t, sameOrigin(testUrl1, testUrl2))
}
