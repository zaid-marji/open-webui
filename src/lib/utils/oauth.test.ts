import { describe, it, expect } from 'vitest';

import {
	getOAuthAutoRedirectPath,
	type AutoRedirectConfig,
	type AutoRedirectContext
} from './oauth';

// An unauthenticated first visit to /auth with no suppressing signals.
const baseContext: AutoRedirectContext = {
	isAuthenticated: false,
	formParam: null,
	errorParam: null,
	hasTokenCookie: false,
	hasLocalStorageToken: false
};

// The canonical SSO-only deployment: one provider, auto_redirect on, local
// login form and LDAP both disabled.
const ssoOnlyConfig: AutoRedirectConfig = {
	oauth: { providers: { oidc: 'SSO' }, auto_redirect: true },
	features: {
		auth: true,
		auth_trusted_header: false,
		enable_login_form: false,
		enable_ldap: false
	},
	onboarding: false
};

describe('getOAuthAutoRedirectPath', () => {
	it('redirects when one provider is configured and auto_redirect is on', () => {
		expect(getOAuthAutoRedirectPath(ssoOnlyConfig, baseContext)).toBe('/oauth/oidc/login');
	});

	it('uses the configured provider key in the path', () => {
		expect(
			getOAuthAutoRedirectPath(
				{ ...ssoOnlyConfig, oauth: { providers: { google: 'Google' }, auto_redirect: true } },
				baseContext
			)
		).toBe('/oauth/google/login');
	});

	it('does not redirect when auto_redirect is off (default)', () => {
		expect(
			getOAuthAutoRedirectPath(
				{ ...ssoOnlyConfig, oauth: { providers: { oidc: 'SSO' }, auto_redirect: false } },
				baseContext
			)
		).toBeNull();
	});

	it('does not redirect when multiple providers are configured', () => {
		expect(
			getOAuthAutoRedirectPath(
				{
					...ssoOnlyConfig,
					oauth: { providers: { google: 'Google', oidc: 'SSO' }, auto_redirect: true }
				},
				baseContext
			)
		).toBeNull();
	});

	it('does not redirect when no providers are configured', () => {
		expect(
			getOAuthAutoRedirectPath(
				{ ...ssoOnlyConfig, oauth: { providers: {}, auto_redirect: true } },
				baseContext
			)
		).toBeNull();
	});

	it('does not redirect when ?form= is present (escape hatch)', () => {
		expect(
			getOAuthAutoRedirectPath(ssoOnlyConfig, { ...baseContext, formParam: 'true' })
		).toBeNull();
	});

	it('does not redirect when ?error= is present so the failure stays visible', () => {
		expect(
			getOAuthAutoRedirectPath(ssoOnlyConfig, {
				...baseContext,
				errorParam: 'Something went wrong'
			})
		).toBeNull();
	});

	it('does not redirect when the user is already authenticated', () => {
		expect(
			getOAuthAutoRedirectPath(ssoOnlyConfig, { ...baseContext, isAuthenticated: true })
		).toBeNull();
	});

	it('does not redirect when a token cookie is present (OAuth callback in flight)', () => {
		expect(
			getOAuthAutoRedirectPath(ssoOnlyConfig, { ...baseContext, hasTokenCookie: true })
		).toBeNull();
	});

	it('does not redirect when a localStorage token is present', () => {
		expect(
			getOAuthAutoRedirectPath(ssoOnlyConfig, { ...baseContext, hasLocalStorageToken: true })
		).toBeNull();
	});

	it('does not redirect when auth is disabled', () => {
		expect(
			getOAuthAutoRedirectPath(
				{
					...ssoOnlyConfig,
					features: { ...ssoOnlyConfig.features, auth: false }
				},
				baseContext
			)
		).toBeNull();
	});

	it('does not redirect in trusted-header auth mode', () => {
		expect(
			getOAuthAutoRedirectPath(
				{
					...ssoOnlyConfig,
					features: { ...ssoOnlyConfig.features, auth_trusted_header: true }
				},
				baseContext
			)
		).toBeNull();
	});

	it('does not redirect when the local login form is enabled', () => {
		expect(
			getOAuthAutoRedirectPath(
				{
					...ssoOnlyConfig,
					features: { ...ssoOnlyConfig.features, enable_login_form: true }
				},
				baseContext
			)
		).toBeNull();
	});

	it('does not redirect when LDAP is enabled', () => {
		expect(
			getOAuthAutoRedirectPath(
				{
					...ssoOnlyConfig,
					features: { ...ssoOnlyConfig.features, enable_ldap: true }
				},
				baseContext
			)
		).toBeNull();
	});

	it('does not redirect when enable_login_form is undefined', () => {
		// SSO-only deployments must be explicit: the absence of a signal that
		// the local form is disabled is not the same as a confirmation.
		expect(
			getOAuthAutoRedirectPath(
				{
					...ssoOnlyConfig,
					features: {
						auth: true,
						auth_trusted_header: false,
						enable_ldap: false
					}
				},
				baseContext
			)
		).toBeNull();
	});

	it('does not redirect when enable_ldap is undefined', () => {
		expect(
			getOAuthAutoRedirectPath(
				{
					...ssoOnlyConfig,
					features: {
						auth: true,
						auth_trusted_header: false,
						enable_login_form: false
					}
				},
				baseContext
			)
		).toBeNull();
	});

	it('does not redirect during first-run onboarding', () => {
		expect(
			getOAuthAutoRedirectPath({ ...ssoOnlyConfig, onboarding: true }, baseContext)
		).toBeNull();
	});

	it('does not redirect when config is missing', () => {
		expect(getOAuthAutoRedirectPath(undefined, baseContext)).toBeNull();
		expect(getOAuthAutoRedirectPath(null, baseContext)).toBeNull();
	});
});
