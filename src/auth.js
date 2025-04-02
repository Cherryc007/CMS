import NextAuth from "next-auth";
import GitHubProvider from "next-auth/providers/github";
import GoogleProvider from "next-auth/providers/google";
import CredentialsProvider from "next-auth/providers/credentials";
import bcrypt from "bcryptjs";
import connectDB from "./lib/connectDB";
import User from "./models/userModel";

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
      id: "credentials",
      name: "Credentials",
      credentials: {
        email: { label: "Email", type: "email", placeholder: "email@example.com" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        await connectDB();

        if (!credentials?.email || !credentials?.password) {
          throw new Error("Email and password are required");
        }

        const user = await User.findOne({ email: credentials.email });

        if (!user) {
          throw new Error("User not found");
        }

        if (!user.password) {
          throw new Error("Please sign in with the provider you used to register");
        }

        const isMatch = await bcrypt.compare(credentials.password, user.password);

        if (!isMatch) {
          throw new Error("Invalid email or password");
        }

        return {
          id: user._id.toString(),
          name: user.name,
          email: user.email,
          role: user.role || "author", // ✅ Default role: "author"
        };
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
