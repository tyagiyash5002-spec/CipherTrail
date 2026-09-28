import React, { createContext, useContext, useState } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { ShieldCheck, LockKeyhole, Eye, EyeOff, ArrowRight, WifiOff, Fingerprint, Layers3, AlertCircle, UserRound, Anchor } from 'lucide-react';
import { Button } from '../components/ui/button';

const AuthContext = createContext(null);
const SESSION_KEY = 'ciphertrail-demo-session';
export const DEMO_CREDENTIALS = { operator: 'navy.operator', password: 'CipherTrail@2026' };
export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    try {
      const stored = JSON.parse(sessionStorage.getItem(SESSION_KEY) || 'null');
      return stored?.id === DEMO_CREDENTIALS.operator && stored?.demo === true ? stored : null;
    } catch { return null; }
  });
  function login(operator, password) {
    if (operator.trim() !== DEMO_CREDENTIALS.operator || password !== DEMO_CREDENTIALS.password) return false;
    const next = { id: DEMO_CREDENTIALS.operator, name: 'Naval Operator', role: 'Demo administrator', demo: true };
    setUser(next);
    try { sessionStorage.setItem(SESSION_KEY, JSON.stringify(next)); } catch { /* In-memory login still works. */ }
    return true;
  }
  function logout() { setUser(null); try { sessionStorage.removeItem(SESSION_KEY); } catch { /* Storage may be disabled. */ } }
  return <AuthContext.Provider value={{ user, login, logout }}>{children}</AuthContext.Provider>;
}
export const useAuth = () => useContext(AuthContext);

export function AuthGate({ children }) {
  const { user } = useAuth();
  const location = useLocation();
  if (!user) return location.pathname === '/login' ? <Login/> : <Navigate to="/login" replace state={{ from: location.pathname }}/>;
  if (location.pathname === '/login') {
    const allowed = ['/', '/documents', '/issuance', '/ledger', '/investigation', '/identities', '/settings'];
    return <Navigate to={allowed.includes(location.state?.from) ? location.state.from : '/'} replace/>;
  }
  return children;
}

function Login() {
  const { login } = useAuth();
  const [operator, setOperator] = useState(''), [password, setPassword] = useState('');
  const [visible, setVisible] = useState(false), [error, setError] = useState('');
  function submit(event) {
    event.preventDefault();
    if (!login(operator, password)) setError('The demo operator ID or password is incorrect. Use the credentials shown below.');
  }
  return <div className="login-page">
    <section className="login-brand-panel">
      <div className="login-brand"><span><ShieldCheck size={29}/></span>CipherTrail<span className="login-brand-dot">.</span></div>
      <div className="login-story"><div className="login-kicker"><Anchor size={16}/> NAVAL SECURITY WORKSPACE</div><h1>Every document.{' '}<br/>Every copy.{' '}<br/><span>Accounted for.</span></h1><p>A clear trail from protected distribution to independently verifiable evidence.</p>
        <div className="login-pillars"><div><LockKeyhole size={21}/><span>Protect the document<small>One payload. Individual access.</small></span></div><div><Fingerprint size={21}/><span>Identify the session<small>A distinct fingerprint for every issuance.</small></span></div><div><Layers3 size={21}/><span>Preserve the evidence<small>Commit before release. Verify offline.</small></span></div></div>
      </div>
      <div className="login-brand-footer"><WifiOff size={16}/><span>Designed for an isolated enclave network</span><span className="login-version">UI DEMO · V1</span></div>
    </section>
    <section className="login-form-panel"><div className="login-form-wrap"><div className="login-form-icon"><ShieldCheck size={27}/></div><div className="eyebrow">WESEE ENCLAVE</div><h2>Welcome to your workspace.</h2><p className="login-intro">Sign in to explore document issuance and forensic workflows.</p>
      <form onSubmit={submit} noValidate={false}>
        <label htmlFor="operator-id">Operator ID</label><div className="login-input"><UserRound size={18}/><input id="operator-id" autoComplete="username" placeholder="Enter your operator ID" value={operator} onChange={e => { setOperator(e.target.value); setError(''); }} required spellCheck={false}/></div>
        <label htmlFor="operator-password">Password</label><div className="login-input"><LockKeyhole size={18}/><input id="operator-password" type={visible ? 'text' : 'password'} autoComplete="current-password" placeholder="Enter your password" value={password} onChange={e => { setPassword(e.target.value); setError(''); }} required/><button type="button" className="icon-button" aria-label={visible ? 'Hide password' : 'Show password'} onClick={() => setVisible(v => !v)}>{visible ? <EyeOff size={18}/> : <Eye size={18}/>}</button></div>
        {error && <div className="login-error" role="alert"><AlertCircle size={17}/>{error}</div>}
        <Button type="submit" className="login-submit">Sign in to demo <ArrowRight size={17}/></Button>
      </form>
      <div className="demo-credentials"><div className="demo-credentials-heading"><span>DEMONSTRATION ACCESS</span><button type="button" onClick={() => { setOperator(DEMO_CREDENTIALS.operator); setPassword(DEMO_CREDENTIALS.password); setError(''); }}>Fill demo credentials</button></div><dl><div><dt>Operator</dt><dd>{DEMO_CREDENTIALS.operator}</dd></div><div><dt>Password</dt><dd>{DEMO_CREDENTIALS.password}</dd></div></dl><p>Local UI simulation only. These public credentials are not production authentication. Do not use a real password.</p></div>
      <div className="login-footnote"><LockKeyhole size={14}/>No credentials are sent to an external service.</div>
    </div><div className="login-copyright">CipherTrail <span>Document attribution workspace</span></div></section>
  </div>;
}
