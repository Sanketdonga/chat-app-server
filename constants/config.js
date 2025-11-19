const corsOptions = {
  origin: [
    "http://localhost:5173",
    "http://localhost:4173",
    process.env.CLIENT_URL,
  ],
  methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: true,
};

// credentials: true :: when your frontend (on 5173/4173) sends requests to backend (like 3000), the browser is allowed to send cookies, auth tokens, etc.

//frontend
//axios.get('http://localhost:3000/api/some-endpoint', { withCredentials: true });

const CHATTU_TOKEN = "chattu-token";

export { corsOptions, CHATTU_TOKEN };
