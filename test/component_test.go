package test

import (
 	"errors"
	"context"
	"testing"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
 	"github.com/aws/smithy-go"
	helper "github.com/cloudposse/test-helpers/pkg/atmos/component-helper"
	"github.com/gruntwork-io/terratest/modules/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type ComponentSuite struct {
	helper.TestSuite
}

func (s *ComponentSuite) TestBasic() {
	const component = "aws-config-bucket/basic"
	const stack = "default-test"
	const awsRegion = "us-east-1"

	defer s.DestroyAtmosComponent(s.T(), component, stack, nil)
	options, _ := s.DeployAtmosComponent(s.T(), component, stack, nil)
	require.NotNil(s.T(), options)

	// Get bucket name from Terraform state - expect format: namespace-tenant-environment-stage-name
	// Based on test fixtures: eg-default-ue2-test-test
	bucketName := "eg-default-ue2-test-test"

	// Verify bucket exists in AWS
	aws.AssertS3BucketExists(s.T(), awsRegion, bucketName)

	// Initialize AWS SDK v2 client
	client, err := s.getS3Client(awsRegion)
	require.NoError(s.T(), err, "Failed to load AWS config")
	ctx := context.Background()

	// Test 1: Verify bucket encryption is enabled (AES256)
	s.T().Run("VerifyEncryption", func(t *testing.T) {
		encryption, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
			Bucket: awsv2.String(bucketName),
		})
		require.NoError(t, err, "Should be able to get bucket encryption")
		require.NotNil(t, encryption.ServerSideEncryptionConfiguration)
		require.NotEmpty(t, encryption.ServerSideEncryptionConfiguration.Rules)

		// Verify AES256 encryption is configured
		rule := encryption.ServerSideEncryptionConfiguration.Rules[0]
		require.NotNil(t, rule.ApplyServerSideEncryptionByDefault)
		assert.Equal(t, s3types.ServerSideEncryptionAes256, rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm)
	})

	// Test 2: Verify versioning is enabled
	s.T().Run("VerifyVersioning", func(t *testing.T) {
		versioning, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
			Bucket: awsv2.String(bucketName),
		})
		require.NoError(t, err, "Should be able to get bucket versioning")
		assert.Equal(t, s3types.BucketVersioningStatusEnabled, versioning.Status, "Versioning should be enabled")
	})

	// Test 3: Verify lifecycle configuration exists
	s.T().Run("VerifyLifecyclePolicy", func(t *testing.T) {
		lifecycle, err := client.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{
			Bucket: awsv2.String(bucketName),
		})
		require.NoError(t, err, "Should be able to get lifecycle configuration")
		require.NotEmpty(t, lifecycle.Rules, "Should have lifecycle rules")

		// Verify lifecycle rule properties based on basic.yaml fixture
		// noncurrent_version_transition_days: 30
		// standard_transition_days: 60
		// glacier_transition_days: 180
		// expiration_days: 365
		// noncurrent_version_expiration_days: 180
		rule := lifecycle.Rules[0]
		assert.Equal(t, s3types.ExpirationStatusEnabled, rule.Status, "Lifecycle rule should be enabled")

		// Check transitions (order-agnostic exact match)
		require.Len(t, rule.Transitions, 2, "Expected 2 transition rules")
		expectedTransitions := []s3types.Transition{
			{Days: awsv2.Int32(60), StorageClass: s3types.TransitionStorageClassStandardIa},
			{Days: awsv2.Int32(180), StorageClass: s3types.TransitionStorageClassGlacier},
		}
		assert.ElementsMatch(t, expectedTransitions, rule.Transitions, "Transition rules should match fixture values")

		// Check noncurrent version transition and expiration
		require.NotEmpty(t, rule.NoncurrentVersionTransitions, "Should have noncurrent version transitions")
		assert.Equal(t, int32(30), awsv2.ToInt32(rule.NoncurrentVersionTransitions[0].NoncurrentDays), "Noncurrent version transition should be 30 days")
		require.NotNil(t, rule.NoncurrentVersionExpiration, "Noncurrent version expiration should be configured")
		assert.Equal(t, int32(180), awsv2.ToInt32(rule.NoncurrentVersionExpiration.NoncurrentDays), "Noncurrent version expiration should be 180 days")

		// Check expiration
		require.NotNil(t, rule.Expiration, "Expiration should be configured")
		assert.Equal(t, int32(365), awsv2.ToInt32(rule.Expiration.Days), "Expiration should be 365 days")
	})

	// Test 4: Verify public access block
	s.T().Run("VerifyPublicAccessBlock", func(t *testing.T) {
		publicAccessBlock, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
			Bucket: awsv2.String(bucketName),
		})
		require.NoError(t, err, "Should be able to get public access block configuration")
		require.NotNil(t, publicAccessBlock.PublicAccessBlockConfiguration)

		// All public access should be blocked
		assert.True(t, awsv2.ToBool(publicAccessBlock.PublicAccessBlockConfiguration.BlockPublicAcls), "BlockPublicAcls should be true")
		assert.True(t, awsv2.ToBool(publicAccessBlock.PublicAccessBlockConfiguration.BlockPublicPolicy), "BlockPublicPolicy should be true")
		assert.True(t, awsv2.ToBool(publicAccessBlock.PublicAccessBlockConfiguration.IgnorePublicAcls), "IgnorePublicAcls should be true")
		assert.True(t, awsv2.ToBool(publicAccessBlock.PublicAccessBlockConfiguration.RestrictPublicBuckets), "RestrictPublicBuckets should be true")
	})

	// Run drift detection
	s.DriftTest(component, stack, nil)
}

func (s *ComponentSuite) TestEnabledFlag() {
	const component = "aws-config-bucket/disabled"
	const stack = "default-test"
	s.VerifyEnabledFlag(component, stack, nil)
}

func (s *ComponentSuite) TestCustomLifecycle() {
	const component = "aws-config-bucket/custom-lifecycle"
	const stack = "default-test"
	const awsRegion = "us-east-1"

	defer s.DestroyAtmosComponent(s.T(), component, stack, nil)
	options, _ := s.DeployAtmosComponent(s.T(), component, stack, nil)
	require.NotNil(s.T(), options)

	// Expected bucket name: eg-default-ue2-test-test-custom
	bucketName := "eg-default-ue2-test-test-custom"

	// Verify bucket exists
	aws.AssertS3BucketExists(s.T(), awsRegion, bucketName)

	// Initialize AWS SDK v2 client
	client, err := s.getS3Client(awsRegion)
	require.NoError(s.T(), err, "Failed to load AWS config")
	ctx := context.Background()

	// Verify custom lifecycle configuration
	s.T().Run("VerifyCustomLifecyclePolicy", func(t *testing.T) {
		lifecycle, err := client.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{
			Bucket: awsv2.String(bucketName),
		})
		require.NoError(t, err, "Should be able to get lifecycle configuration")
		require.NotEmpty(t, lifecycle.Rules, "Should have lifecycle rules")

		// Verify custom lifecycle properties
		// noncurrent_version_transition_days: 15
		// standard_transition_days: 30
		// glacier_transition_days: 90
		// expiration_days: 180
		// noncurrent_version_expiration_days: 90
		rule := lifecycle.Rules[0]
		assert.Equal(t, s3types.ExpirationStatusEnabled, rule.Status, "Lifecycle rule should be enabled")

		// Check transitions (order-agnostic exact match)
		require.Len(t, rule.Transitions, 2, "Expected 2 transition rules")
		expectedTransitions := []s3types.Transition{
			{Days: awsv2.Int32(30), StorageClass: s3types.TransitionStorageClassStandardIa},
			{Days: awsv2.Int32(90), StorageClass: s3types.TransitionStorageClassGlacier},
		}
		assert.ElementsMatch(t, expectedTransitions, rule.Transitions, "Transition rules should match custom lifecycle values")

		// Check noncurrent version transition and expiration
		require.NotEmpty(t, rule.NoncurrentVersionTransitions, "Should have noncurrent version transitions")
		assert.Equal(t, int32(15), awsv2.ToInt32(rule.NoncurrentVersionTransitions[0].NoncurrentDays), "Noncurrent version transition should be 15 days")
		require.NotNil(t, rule.NoncurrentVersionExpiration, "Noncurrent version expiration should be configured")
		assert.Equal(t, int32(90), awsv2.ToInt32(rule.NoncurrentVersionExpiration.NoncurrentDays), "Noncurrent version expiration should be 90 days")

		// Verify expiration matches custom value (180 days)
		require.NotNil(t, rule.Expiration, "Expiration should be configured")
		assert.Equal(t, int32(180), awsv2.ToInt32(rule.Expiration.Days), "Expiration should be 180 days")
	})

	// Run drift detection
	s.DriftTest(component, stack, nil)
}

func (s *ComponentSuite) TestNoLifecycle() {
	const component = "aws-config-bucket/no-lifecycle"
	const stack = "default-test"
	const awsRegion = "us-east-1"

	defer s.DestroyAtmosComponent(s.T(), component, stack, nil)
	options, _ := s.DeployAtmosComponent(s.T(), component, stack, nil)
	require.NotNil(s.T(), options)

	// Expected bucket name: eg-default-ue2-test-test-no-lifecycle
	bucketName := "eg-default-ue2-test-test-no-lifecycle"

	// Verify bucket exists
	aws.AssertS3BucketExists(s.T(), awsRegion, bucketName)

	// Initialize AWS SDK v2 client
	client, err := s.getS3Client(awsRegion)
	require.NoError(s.T(), err, "Failed to load AWS config")
	ctx := context.Background()

	// Verify lifecycle is disabled
	s.T().Run("VerifyNoLifecyclePolicy", func(t *testing.T) {
		_, err := client.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{
			Bucket: awsv2.String(bucketName),
		})
		// When lifecycle_rule_enabled is false, the API should return NoSuchLifecycleConfiguration
		require.Error(t, err, "Should get an error when no lifecycle configuration exists")
		var apiErr smithy.APIError
		require.True(t, errors.As(err, &apiErr), "Expected smithy.APIError for lifecycle lookup")
		assert.Equal(t, "NoSuchLifecycleConfiguration", apiErr.ErrorCode(), "Unexpected error when lifecycle configuration is absent")
	})

	// Verify encryption and versioning still work
	s.T().Run("VerifyEncryptionWithoutLifecycle", func(t *testing.T) {
		encryption, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
			Bucket: awsv2.String(bucketName),
		})
		require.NoError(t, err, "Should be able to get bucket encryption")
		require.NotNil(t, encryption.ServerSideEncryptionConfiguration)

		rule := encryption.ServerSideEncryptionConfiguration.Rules[0]
		assert.Equal(t, s3types.ServerSideEncryptionAes256, rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm)
	})

	// Run drift detection
	s.DriftTest(component, stack, nil)
}

// Helper function to get S3 client
func (s *ComponentSuite) getS3Client(region string) (*s3.Client, error) {
	ctx := context.Background()
	cfg, err := awsConfig.LoadDefaultConfig(ctx, awsConfig.WithRegion(region))
	if err != nil {
		return nil, err
	}
	return s3.NewFromConfig(cfg), nil
}

// TestRunSuite runs the ComponentSuite test suite
func TestRunSuite(t *testing.T) {
	suite := new(ComponentSuite)
	helper.Run(t, suite)
}
