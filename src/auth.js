import NextAuth from "next-auth";
import GitHubProvider from "next-auth/providers/github";
import CredentialsProvider from "next-auth/providers/credentials";
import bcrypt from "bcryptjs";
import connectDB from "./lib/connectDB";
import User from "./models/userModel";
import GoogleProvider from "next-auth/providers/google";

export const { handlers, signIn, signOut, auth } = NextAuth({
  secret: process.env.NEXTAUTH_SECRET,
  providers: [
    GitHubProvider({
      clientId: process.env.GITHUB_ID,
      clientSecret: process.env.GITHUB_SECRET,
    }),
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    }),
    CredentialsProvider({
      // The name to display on the sign in form (e.g. "Sign in with...")
      id: "credentials",
      name: "Credentials",
      // `credentials` is used to generate a form on the sign in page.
      // You can specify which fields should be submitted, by adding keys to the `credentials` object.
      // e.g. domain, username, password, 2FA token, etc.
      // You can pass any HTML attribute to the <input> tag through the object.
      credentials: {
        email: { label: "Email", type: "email", placeholder: "email@example.com" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials, req) {
        try {
          // Add logic here to look up the user from the credentials supplied
          await connectDB();
          
          if (!credentials?.email || !credentials?.password) {
            throw new Error("Email and password are required");
          }

          const user = await User.findOne({
            email: credentials.email,
          });

          if (!user) {
            throw new Error("User not found");
          }

          // Check if the user has a password (they might have signed up with OAuth)
          if (!user.password) {
            throw new Error("Please sign in with the provider you used to register");
          }

          const isMatch = await bcrypt.compare(
            credentials.password,
            user.password
          );

          if (!isMatch) {
            throw new Error("Invalid email or password");
          }

          // Return user object with required fields for next-auth
          return {
            id: user._id.toString(),
            name: user.name,
            email: user.email,
            role: user.role || "author",
          };
        } catch (error) {
          console.error("Authorize error:", error);
          throw new Error(error.message || "Authentication failed");
        }
      },
    }),
  ],
  callbacks: {
    async signIn({ user, account }) {
      if (account && (account.provider === "google" || account.provider === "github")) {
        await connectDB();
        
        let existingUser = await User.findOne({ email: user.email });
  
        if (!existingUser) {
          // Directly create the user in MongoDB instead of calling an API
          existingUser = await User.create({
            name: user.name,
            email: user.email,
            password: "", // OAuth users don't have a password
            role: "author", // ✅ Default role: "author"
            isVerified: true,
          });
        }
  
        // Ensure the role is assigned
        user.role = existingUser.role || "author"; 
      }
  
      return true;
    },
  
    async jwt({ token, user }) {
      if (user) {
        token.id = user.id || user._id?.toString(); // ✅ Ensure correct ID storage
        token.email = user.email;
        token.name = user.name;
        token.role = user.role || "author"; // ✅ Default to "author" if missing
      }
      return token;
    },
  
    async session({ session, token }) {
      if (token) {
        session.user = {
          id: token.id,
          email: token.email,
          name: token.name,
          role: token.role || "author", // ✅ Ensure role is always present
        };
      }
      return session;
    },
  
    async redirect({ url, baseUrl }) {
      return baseUrl;
    },
  },
  
  pages: {
    signIn: "/login",
    error: "/login",
  },
});
export { handler as GET, handler as POST };