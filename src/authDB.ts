import bcrypt from 'bcrypt';

export interface User {
  username: string;
  password: string;
}

export interface AuthDBFacade {
  saveUser(user: User): Promise<void>;
  getUser(username: string): Promise<User | null>;
  isTokenBlacklisted(token: string): Promise<boolean>;
  blacklistToken(token: string): Promise<void>;
}

export const createInMemoryAuthDB: () => AuthDBFacade = () => {
  const USER_STORE: Record<string, any> = {
    'a@a.com': {
      username: 'a@a.com',
      password: bcrypt.hashSync('asdfasdf', 10),
    },
  };
  const BLACKLISTED_TOKENS_STORE: Set<string> = new Set();

  return {
    saveUser(user) {
      USER_STORE[user.username] = {
        username: user.username,
        password: user.password,
      };
      return Promise.resolve();
    },

    getUser(username) {
      const user = USER_STORE[username] ?? null;
      return Promise.resolve(user);
    },

    isTokenBlacklisted(token) {
      return Promise.resolve(BLACKLISTED_TOKENS_STORE.has(token));
    },

    blacklistToken(token) {
      BLACKLISTED_TOKENS_STORE.add(token);
      return Promise.resolve();
    },
  };
};
