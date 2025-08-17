export const USER_ROLES = {
  user: "USER",
  admin: "ADMIN",
  super_admin: "SUPER_ADMIN",
} as const;

export const ALL_USER_ROLES = Object.values(USER_ROLES);
