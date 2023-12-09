// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of K9s

package view

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/derailed/k9s/internal/client"
	"github.com/derailed/k9s/internal/ui"
	"github.com/derailed/tcell/v2"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"log"
	"sigs.k8s.io/yaml"
)

// Secret presents a secret viewer.
type Secret struct {
	ResourceViewer
}

// NewSecret returns a new viewer.
func NewSecret(gvr client.GVR) ResourceViewer {
	s := Secret{
		ResourceViewer: NewBrowser(gvr),
	}
	s.AddBindKeysFn(s.bindKeys)

	return &s
}

func (s *Secret) bindKeys(aa ui.KeyActions) {
	aa.Add(ui.KeyActions{
		ui.KeyX: ui.NewKeyAction("Decode", s.decodeCmd, true),
		ui.KeyB: ui.NewKeyAction("Decode Base64", s.decodeCRT, true),
		ui.KeyU: ui.NewKeyAction("UsedBy", s.refCmd, true),
	})
}

func (s *Secret) refCmd(evt *tcell.EventKey) *tcell.EventKey {
	return scanRefs(evt, s.App(), s.GetTable(), "v1/secrets")
}

func (s *Secret) decodeCmd(evt *tcell.EventKey) *tcell.EventKey {
	path := s.GetTable().GetSelectedItem()
	if path == "" {
		return evt
	}

	o, err := s.App().factory.Get(s.GVR().String(), path, true, labels.Everything())
	if err != nil {
		s.App().Flash().Err(err)
		return nil
	}

	var secret v1.Secret
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(o.(*unstructured.Unstructured).Object, &secret)
	if err != nil {
		s.App().Flash().Err(err)
		return nil
	}

	d := make(map[string]string, len(secret.Data))
	for k, val := range secret.Data {
		d[k] = string(val)
	}
	raw, err := yaml.Marshal(d)
	if err != nil {
		s.App().Flash().Errf("Error decoding secret %s", err)
		return nil
	}

	details := NewDetails(s.App(), "Secret Decoder", path, contentYAML, true).Update(string(raw))
	if err := s.App().inject(details, false); err != nil {
		s.App().Flash().Err(err)
	}

	return nil
}

// do hand.
func (s *Secret) decodeCRT(evt *tcell.EventKey) *tcell.EventKey {
	path := s.GetTable().GetSelectedItem()
	if path == "" {
		return evt
	}

	o, err := s.App().factory.Get(s.GVR().String(), path, true, labels.Everything())
	if err != nil {
		s.App().Flash().Err(err)
		return nil
	}

	var secret v1.Secret
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(o.(*unstructured.Unstructured).Object, &secret)
	if err != nil {
		s.App().Flash().Err(err)
		return nil
	}

	d := make(map[string]string, len(secret.Data))
	for k, val := range secret.Data {
		if k == "ca.crt" {
			block, _ := pem.Decode(val)
			if block == nil {
				log.Fatal("Failed to decode PEM certificate")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				log.Fatal(err)
			}
			certFunc := []string{
				"Subject: " + cert.Subject.CommonName,
				"Issuer: " + cert.Issuer.CommonName,
				"StartTime: " + cert.NotBefore.String(),
				"EndTime: " + cert.NotAfter.String(),
				"SignatureAlgorithm: " + cert.SignatureAlgorithm.String(),
			}
			certContent := ""
			for _, v := range certFunc {
				certContent += fmt.Sprintf("%s\n", v)
			}
			d[k] = certContent
		} else {
			d[k] = string(val)
		}
	}
	raw, err := yaml.Marshal(d)
	if err != nil {
		s.App().Flash().Errf("Error decoding secret %s", err)
		return nil
	}

	details := NewDetails(s.App(), "Secret Decoder", path, contentYAML, true).Update(string(raw))
	if err := s.App().inject(details, false); err != nil {
		s.App().Flash().Err(err)
	}

	return nil
}
