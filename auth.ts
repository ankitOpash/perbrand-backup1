// REVIEW:
// @ts-nocheck

import NextAuth, { NextAuthConfig } from "next-auth";
import { authMiddlewareOptions } from "@/auth.middleware.config";
import { getUserByEmail } from "./lib/getUser";
import { db } from "./lib/prisma";
import { PrismaAdapter } from "@auth/prisma-adapter";
import GoogleProvider from "@auth/core/providers/google";
import CredentialsProvider from "@auth/core/providers/credentials";
import EmailProvider from "@auth/core/providers/email";
import LinkedInProvider from "next-auth/providers/linkedin";
import DiscordProvider from "next-auth/providers/discord";
import { config } from "./config/shipper.config";
import bcrypt from "bcryptjs";

export const authOptions = {
  adapter: PrismaAdapter(db),
  providers: [
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    }),
    DiscordProvider({
      clientId: process.env.DISCORD_CLIENT_ID,
      clientSecret: process.env.DISCORD_CLIENT_SECRET,
      scope: ["identify", "email"], // Request scopes you need
    }),
    // LinkedInProvider({
    //   clientId: process.env.LINKEDIN_CLIENT_ID as string,
    //   clientSecret: process.env.LINKEDIN_CLIENT_SECRET as string,
    //   authorization: {
    //     params: { scope: "openid profile email" },
    //   },
    //   token_endpoint_auth_method: "client_secret_post",
    //  issuer: "https://www.linkedin.com",
    //    jwks_endpoint: "https://www.linkedin.com/oauth/openid/jwks",
    //   profile(profile) {
    //     const defaultImage =
    //       "https://cdn-icons-png.flaticon.com/512/174/174857.png";
    //     return {
    //       id: profile.sub,
    //       name: profile.name,
    //       email: profile.email,
    //       image: profile.picture ?? defaultImage,
    //     };
    //   },
    // }),
    LinkedInProvider({
      clientId: process.env.LINKEDIN_CLIENT_ID,
      clientSecret: process.env.LINKEDIN_CLIENT_SECRET,
      client: { token_endpoint_auth_method: "client_secret_post" },
      userinfo: {
        url: "https://api.linkedin.com/v2/userinfo",
      },
      authorization: {
        url: "https://www.linkedin.com/oauth/v2/authorization",
        params: {
          scope: "profile email openid",
          prompt: "consent",
          access_type: "offline",
          response_type: "code",
        },
      },
      token: {
        url: "https://www.linkedin.com/oauth/v2/accessToken",
        params: {},
      },
      async profile(profile) {
        return {
          id: profile.sub,
          name: profile.name,
          firstname: profile.given_name,
          lastname: profile.family_name,
          email: profile.email,
        };
      },
      idToken: true,
      checks: ["pkce"],
      scope: "r_liteprofile r_emailaddress",
      issuer: "https://www.linkedin.com",
      tokenUri: "https://www.linkedin.com/oauth/v2/accessToken",
      wellKnown:
        "https://www.linkedin.com/oauth/.well-known/openid-configuration",
      jwks_endpoint: "https://www.linkedin.com/oauth/openid/jwks",
      signinUrl: "http://localhost:3000/api/auth/signin/linkedin",
      callbackUrl: "http://localhost:3000/api/auth/callback/linkedin",
    }),

    CredentialsProvider({
      name: "credentials",
      credentials: {
        email: { label: "Email", type: "text", placeholder: " " },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        if (!credentials?.email || !credentials?.password) {
          throw new Error("Missing credentials");
        }
        const user = await getUserByEmail(credentials.email);

        if (!user || !user?.hashedPassword) {
          throw new Error("Invalid credentials Custom");
        }

        const isCorrectPassword = await bcrypt.compare(
          credentials.password,
          user.hashedPassword
        );
        if (!isCorrectPassword) {
          console.log("Invalid credentials Custom", isCorrectPassword);
          console.log("credentials.password", credentials.password);
          throw new Error("Invalid credentials Custom");
        }
        return user;
      },
    }),

    EmailProvider({
      server: {
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT),
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASSWORD,
        },
      },
      from: config.email.fromNoReply,
    }),
  ],

  //   pages: {
  //     signIn: "/auth/login",
  //     signOut: "/auth/logout",
  //     error: "/auth/error",
  //     verifyRequest: "/auth/verify-request",
  //     newUser: "/auth/new-user",
  //   },
  // custom pages
  //   pages: {
  //     signIn: "/",
  //     newUser: "/", // New users will be directed here on first sign in
  //     error: "/auth/error",
  //   },

  debug: process.env.NODE_ENV === "development",
  jwt: {
    secret: process.env.JWT_SECRET,
  },

  session: {
    maxAge: 30 * 24 * 60 * 60,
    strategy: "jwt",
  },

  callbacks: {
    async signIn({ user, account, profile, email, credentials }) {
      console.log("from signin", { user });
      console.log("from signin", { account });
      console.log("from signin", { profile });

      if (account?.provider !== "email") return true;

      const userExists = await db.user.findUnique({
        where: { email: user.email! },
      });
      if (userExists) {
        return true;
      } else {
        return false;
      }
    },

    async redirect({ url, baseUrl }) {
      if (url.startsWith("/")) return `${baseUrl}${url}`;
      else if (new URL(url).origin === baseUrl) return url;
      return baseUrl;
    },

    async jwt({ token, user, account, profile, session, trigger }) {
      if (user) {
        token.id = user.id;
        token.email = user.email;
        token.name = user.name;
        token.role = user.role;
      }

      return token;
    },

    async session({ session, token, user }) {
      //const favoriteTattooIds = await UserService.getFavoriteTattooIds(user);
      const favoriteTattooIds = await UserService.getFavoriteTattooIds(user);

      if (session && session.user) {
      }
      return {
        ...session,
        user: {
          ...session.user,
          id: token.id,
          role: token.role,
        },
      };
    },
  },

  // We also have "events"
  // what's the difference between callbacks and events?
  // callbacks modify the default behavior, events can be used to add on top of the default behavior
  // async signIn(message) { /* on successful sign in */ },
  // async signOut(message) { /* on signout */ },
  // async createUser(message) { /* user created */ },
  // async updateUser(message) { /* user updated - e.g. their email was verified */ },
  // async linkAccount(message) { /* account (e.g. Twitter) linked to a user */ },
  // async session(message) { /* session is active */ },

  // https://dev.to/mfts/how-to-send-a-warm-welcome-email-with-resend-next-auth-and-react-email-576f
  // events: {
  //     async createUser(message) {
  //       const params = {
  //         user: {
  //           name: message.user.name,
  //           email: message.user.email,
  //         },
  //       };
  //       await sendWelcomeEmail(params); // <-- send welcome email
  //     }
  //   },

  //REVIEW: When you supply a session prop in _app.js, useSession won't show a loading state,
  // as it'll already have the session available. In this way, you can provide a more seamless user experience.
  // https://next-auth.js.org/tutorials/securing-pages-and-api-routes
} satisfies NextAuthConfig;

export const {
  handlers: { GET, POST },
  auth,
  signIn,
  signOut,
  update,
} = NextAuth({
  ...authMiddlewareOptions,
  ...authOptions,
});
