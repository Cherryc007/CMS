import { NextResponse } from "next/server";
import { getToken } from "next-auth/jwt";

export default async function middleware(request) {
  const path = request.nextUrl.pathname;
  console.log(`🔍 Requested Path: ${path}`);

  // Get the auth token
  const token = await getToken({ req: request, secret: process.env.NEXTAUTH_SECRET });
  console.log("🔑 Token Data:", token);

  // Check if the user is authenticated
  const isAuthenticated = !!token;
  console.log(`✅ Is Authenticated: ${isAuthenticated}`);

  // Public paths that don't require authentication
  const isPublicPath = path === '/' || path === '/login' || path === '/register' || path === "/signup";

  // Common paths for all authenticated users
  const isCommonAuthPath = path === '/home';

  // Redirect to login if not authenticated and accessing a protected page
  if (!isAuthenticated && !isPublicPath) {
    console.log(`🔴 Not Authenticated: Redirecting to /login`);
    return NextResponse.redirect(new URL('/login', request.url));
  }

  // Redirect to home if already authenticated but trying to access login/register
  if (isAuthenticated && isPublicPath) {
    console.log(`🟡 Authenticated User Trying to Access Public Path: Redirecting to /home`);
    return NextResponse.redirect(new URL('/home', request.url));
  }

  // Allow access to common authenticated paths
  if (isAuthenticated && isCommonAuthPath) {
    console.log(`🟢 Authenticated User Accessing Common Page: Allowing Access`);
    return NextResponse.next();
  }

  // Role-based access control
  if (isAuthenticated) {
    console.log(`🛑 Role-Based Access Check for ${token.role}`);

    // Admin-only routes
    if (path.startsWith('/admin-dashboard') || path === '/conference-creation' || path === '/admin-dashboard/create-post') {
      if (token.role !== 'admin') {
        console.log(`🔒 Access Denied for ${token.role}: Redirecting to /home`);
        return NextResponse.redirect(new URL('/home', request.url));
      }
    }

    // Author-only routes
    if (path.startsWith('/author-dashboard')) {
      if (token.role !== 'author') {
        console.log(`🔒 Access Denied for ${token.role}: Redirecting to /home`);
        return NextResponse.redirect(new URL('/home', request.url));
      }
    }

    // Reviewer-only routes
    if (path.startsWith('/reviewer-dashboard') || path.startsWith('/review-paper')) {
      if (token.role !== 'reviewer') {
        console.log(`🔒 Access Denied for ${token.role}: Redirecting to /home`);
        return NextResponse.redirect(new URL('/home', request.url));
      }
    }
  }

  console.log(`✅ Access Granted: Proceeding with Request`);
  return NextResponse.next();
}

export const config = {
  matcher: [
    '/((?!api|_next/static|_next/image|favicon.ico).*)',
    '/admin-dashboard/:path*',
    '/author-dashboard/:path*',
    '/reviewer-dashboard/:path*',
    '/review-paper/:path*',
    '/conference-creation',
    '/admin-dashboard/create-post',
    '/home'
  ],
};
