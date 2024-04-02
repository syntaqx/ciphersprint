package main

import "testing"

func TestIsValidEmail(t *testing.T) {
	tests := []struct {
		email    string
		expected bool
	}{
		{
			email:    "test@example.com",
			expected: true,
		},
		{
			email:    "invalid_email",
			expected: false,
		},
		// Add more test cases as needed
	}

	for _, tt := range tests {
		t.Run(tt.email, func(t *testing.T) {
			result := isValidEmail(tt.email)
			if result != tt.expected {
				t.Errorf("Expected %v for email %s, but got %v", tt.expected, tt.email, result)
			}
		})
	}
}
