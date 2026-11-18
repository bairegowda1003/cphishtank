import { createContext, useContext, useEffect, useState } from "react";
import { api, clearToken, getToken, storeToken } from "./api";

const Ctx = createContext(null);
export const useAuth = () => useContext(Ctx);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [ready, setReady] = useState(!getToken());

  useEffect(() => {
    const expire = () => {
      clearToken();
      setUser(null);
      setReady(true);
    };
    window.addEventListener("cpt:unauthorized", expire);
    if (!getToken()) return () => window.removeEventListener("cpt:unauthorized", expire);
    api.me().then(setUser).catch(expire).finally(() => setReady(true));
    return () => window.removeEventListener("cpt:unauthorized", expire);
  }, []);

  const finish = (res, rememberMe) => {
    storeToken(res.access_token, rememberMe);
    setUser(res.user);
    return res.user;
  };
  const value = {
    user,
    ready,
    login: async (body) => finish(await api.login(body), body.remember_me),
    logout: () => { clearToken(); setUser(null); },
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
