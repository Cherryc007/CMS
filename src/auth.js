import NextAuth from "next-auth";
import GitHubProvider from "next-auth/providers/github";
import GoogleProvider from "next-auth/providers/google";
import CredentialsProvider from "next-auth/providers/credentials";
import bcrypt from "bcryptjs";
import connectDB from "./lib/connectDB";
import User from "./models/userModel";

export default NextAuth({
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
          role: user.role || "author",
        };
      },
    }),
  ],
  callbacks: {
    async signIn({ user, account }) {
      await connectDB();

      if (account.provider === "google" || account.provider === "github") {
        try {
          let existingUser = await User.findOne({ email: user.email });

          if (!existingUser) {
            existingUser = new User({
              name: user.name,
              email: user.email,
              password: "", // OAuth users don’t have a password
              role: "author",
              isVerified: true,
            });
            await existingUser.save();
          }

          user.id = existingUser._id.toString(); // ✅ Ensure correct MongoDB ID
          user.role = existingUser.role || "author"; // ✅ Ensure role is set

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
        token.id = user.id; // ✅ Correct user ID assignment
        token.email = user.email;
        token.name = user.name;
        token.role = user.role || "author"; // ✅ Ensure role is stored
      }
      return token;
    },
    async session({ session, token }) {
      if (token) {
        session.user.id = token.id; // ✅ Ensure session gets correct user ID
        session.user.email = token.email;
        session.user.name = token.name;
        session.user.role = token.role; // ✅ Ensure role is available in session
      }
      return session;
    },
  },
  pages: {
    signIn: "/login",
    error: "/login",
  },
});
