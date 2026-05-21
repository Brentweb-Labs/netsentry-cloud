import { HttpInterceptorFn } from '@angular/common/http';

const TOKEN_KEY = 'idps_token';

export const apiKeyInterceptor: HttpInterceptorFn = (req, next) => {
  const token = localStorage.getItem(TOKEN_KEY);
  if (!token) return next(req);
  return next(req.clone({ setHeaders: { Authorization: `Bearer ${token}` } }));
};
