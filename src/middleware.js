import { NextResponse } from "next/server";
import { getToken } from "next-auth/jwt";

export default async function middleware(request) {
  const path = request.nextUrl.pathname;
  console.log(`🌍 Incoming Request Path: ${path}`);

  // Get the token using next-auth
  const token = await getToken({ req: request, secret: process.env.NEXTAUTH_SECRET });
  console.log("🔑 Token Data:", token);

  const isAuthenticated = !!token;
  console.log(`✅ Authenticated: ${isAuthenticated}`);

  const isPublicPath = path === '/' || path === '/login' || path === '/register';
  const isCommonAuthPath = path === '/home';

  if (!isAuthenticated && !isPublicPath) {
    console.log("🚫 Not authenticated, redirecting to /login");
    return NextResponse.redirect(new URL('/login', request.url));
  }

  if (isAuthenticated && isPublicPath) {
    console.log("🔄 Already authenticated, redirecting to /home");
    return NextResponse.redirect(new URL('/home', request.url));
  }

  if (isAuthenticated && isCommonAuthPath) {
    console.log("✅ Authenticated user accessing a common page");
    return NextResponse.next();
  }

  if (isAuthenticated) {
    console.log(`🛡️ Role-Based Access Check for: ${token.role}`);

    if (path.startsWith('/admin-dashboard') || 
        path === '/conference-creation' || 
        path === '/admin-dashboard/create-post') {
      if (token.role !== 'admin') {
        console.log("⛔ Access Denied: Not an Admin, redirecting to /home");
        return NextResponse.redirect(new URL('/home', request.url));
      }
    }

    if (path.startsWith('/author-dashboard')) {
      if (token.role !== 'author') {
        console.log("⛔ Access Denied: Not an Author, redirecting to /home");
        return NextResponse.redirect(new URL('/home', request.url));
      }
    }

    if (path.startsWith('/reviewer-dashboard') || path.startsWith('/review-paper')) {
      if (token.role !== 'reviewer') {
        console.log("⛔ Access Denied: Not a Reviewer, redirecting to /home");
        return NextResponse.redirect(new URL('/home', request.url));
      }
    }
  }

  console.log("✅ Access Granted: Proceeding to next response");
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
