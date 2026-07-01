// internal/handlers/helpers.go
// Shared handler helpers, type aliases, and common logic.
package handlers

import "github.com/yourdomain/saas-iam/internal/auth"

// models_UserRole is a local type alias for the models.UserRole string
// used within handler code to avoid importing the models package.
type models_UserRole = string

// resolveRoleStr returns the actor's application-level role name.
func resolveRoleStr(claims *auth.Claims) string {
	if claims == nil {
		return "end_user"
	}
	if claims.HasRole("super_admin") {
		return "super_admin"
	}
	if claims.HasRole("realm_admin") || claims.HasRole("manage-realm") {
		return "realm_admin"
	}
	return "end_user"
}
