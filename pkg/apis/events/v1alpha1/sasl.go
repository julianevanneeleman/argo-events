package v1alpha1

import corev1 "k8s.io/api/core/v1"

// SASLConfig refers to SASL configuration for a client
type SASLConfig struct {
	// SASLMechanism is the name of the enabled SASL mechanism.
	// Possible values: OAUTHBEARER, PLAIN (defaults to PLAIN).
	// +optional
	Mechanism string `json:"mechanism,omitempty" protobuf:"bytes,1,opt,name=mechanism"`
	// User is the authentication identity (authcid) to present for
	// SASL/PLAIN or SASL/SCRAM authentication
	// +optional
	UserSecret *corev1.SecretKeySelector `json:"userSecret,omitempty" protobuf:"bytes,2,opt,name=userSecret"`
	// Password for SASL/PLAIN authentication
	// +optional
	PasswordSecret *corev1.SecretKeySelector `json:"passwordSecret,omitempty" protobuf:"bytes,3,opt,name=passwordSecret"`
	// AWS region used by TokenProvider for SASL/AWS-MSK-IAM authentication
	// +optional
	AwsRegion string `json:"awsRegion,omitempty" protobuf:"bytes,4,opt,name=awsRegion"`
}

func (s SASLConfig) GetMechanism() string {
	switch s.Mechanism {
	case "AWS-MSK-IAM":
		return "OAUTHBEARER"
	case "OAUTHBEARER", "SCRAM-SHA-256", "SCRAM-SHA-512", "GSSAPI":
		return s.Mechanism
	default:
		// default to PLAINTEXT mechanism
		return "PLAIN"
	}
}
