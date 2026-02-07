/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run `npm run dev` in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run `npm run deploy` to publish your worker
 *
 * Bind resources to your worker in `wrangler.jsonc`. After adding bindings, a type definition for the
 * `Env` object can be regenerated with `npm run cf-typegen`.
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */
import { jwtVerify, createRemoteJWKSet } from 'jose';
import * as Sentry from '@sentry/cloudflare';

interface Env {
	SENTRY_DSN: string;
	POLICY_AUD: string;
	TEAM_DOMAIN: string;
	A_SERVICE: string;
	J_SERVICE: string;
}
export default Sentry.withSentry(
	(env: Env) => ({
		dsn: env.SENTRY_DSN,
		sendDefaultPii: true,
	}),
	{
		async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
			return run(request, env, ctx);
		},
	} satisfies ExportedHandler<Env>,
);

async function run(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
	if (!env.POLICY_AUD) {
		return new Response('Missing required audience', {
			status: 403,
			headers: { 'Content-Type': 'text/plain' },
		});
	}

	// Get the JWT from the request headers
	const token = request.headers.get('cf-access-jwt-assertion');

	// Check if token exists
	if (!token) {
		return new Response('Missing required CF Access JWT', {
			status: 403,
			headers: { 'Content-Type': 'text/plain' },
		});
	}

	try {
		// Create JWKS from your team domain
		const JWKS = createRemoteJWKSet(new URL(`${env.TEAM_DOMAIN}/cdn-cgi/access/certs`));

		// Verify the JWT
		const { payload } = await jwtVerify(token, JWKS, {
			issuer: env.TEAM_DOMAIN,
			audience: env.POLICY_AUD,
		});
		const url = new URL(request.url);
		const service = url.searchParams.get('service') || 'unknown';
		if (service === 'unknown') {
			return new Response('Missing required service parameter', {
				status: 400,
				headers: { 'Content-Type': 'text/plain' },
			});
		}
		// Token is valid, proceed with your application logic
		return await route(env, service);
	} catch (error) {
		// Token verification failed
		const message = error instanceof Error ? error.message : 'Unknown error';
		return new Response(`Invalid token: ${message}`, {
			status: 403,
			headers: { 'Content-Type': 'text/plain' },
		});
	}
}

async function route(env: Env, service: string): Promise<Response> {
	switch (service) {
		case 'A':
			return await handleServiceA(env);
		case 'J':
			return await handleServiceJ(env);
		default:
			return new Response('Missing required audience', {
				status: 403,
				headers: { 'Content-Type': 'text/plain' },
			});
	}
}

async function handleServiceA(env: Env): Promise<Response> {
	const url = env.A_SERVICE;
	const response = await fetch(url);
	return response;
}

async function handleServiceJ(env: Env): Promise<Response> {
	const url = env.J_SERVICE;
	const response = await fetch(url);
	const urls = atob(await response.text())
		.split('\n')
		.map((u) => new URL(u));
	let r = [];
	for (const url of urls) {
		const data = atob(url.host);
		if (url.protocol === 'ss:') {
			const ss = new URL(`ss://${data}`);
			r.push(
				`${url.hash.slice(1)} = ss, ${ss.hostname}, ${ss.port}, encrypt-method=${ss.username}, password=${ss.password}, udp-relay=true`,
			);
		} else if (url.protocol === 'vmess:') {
			const vmess = JSON.parse(data);
			r.push(`${vmess.ps} = vmess, ${vmess.add}, ${vmess.port}, username=${vmess.id}, skip-cert-verify=true, tls=true`);
		}
	}
	return new Response(r.join('\n'));
}
