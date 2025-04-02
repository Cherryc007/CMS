import GitHubProvider from "next-auth/providers/github";
import CredentialsProvider from "next-auth/providers/credentials";
import bcrypt from "bcryptjs";
import connectDB from "./connectDB";
import User from "../models/userModel";
import GoogleProvider from "next-auth/providers/google";

const authOptions = {
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
      async authorize(credentials, req) {
        await connectDB();

        if (!credentials?.email || !credentials?.password) {
          throw new Error("Email and password are required");
        }

        const user = await User.findOne({ email: credentials.email });

        if (!user) throw new Error("User not found");
        if (!user.password) throw new Error("Please sign in with OAuth");

        const isMatch = await bcrypt.compare(credentials.password, user.password);
        if (!isMatch) throw new Error("Invalid credentials");

        return { id: user._id.toString(), name: user.name, email: user.email, role: user.role || "author" };
      },
    }),
  ],
  callbacks: {
    async signIn({ user, account, profile }) {
      if (account.provider === "google" || account.provider === "github") {
        await connectDB();

        try {
          let existingUser = await User.findOne({ email: user.email });

          if (!existingUser) {
            existingUser = new User({
              name: user.name || profile.name,
              email: user.email,
              password: "", 
              role: "author",
              isVerified: true,
            });

            await existingUser.save();
          }

          user.id = existingUser._id.toString();
          user.role = existingUser.role || "author"; 

          return true;
        } catch (error) {
          console.error("Sign-in error:", error);
          return false; 
        }
      }
      return true;
    },

    async jwt({ token, user }) {
      if (user) {
        token.id = user.id;
        token.email = user.email;
        token.name = user.name;
        token.role = user.role || "author";
      }
      return token;
    },
    async session({ session, token }) {
      if (token) {
        session.user.id = token.id;
        session.user.email = token.email;
        session.user.name = token.name;
        session.user.role = token.role || "author";
      }
      return session;
    }
  },
  pages: {
    signIn: "/login",
    error: "/login",
  },
};

export default authOptions;
