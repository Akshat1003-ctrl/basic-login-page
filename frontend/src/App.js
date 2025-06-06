import React, { useState, useMemo, useEffect } from 'react';
import axios from 'axios';
import { Toaster, toast } from 'sonner';

// --- Helper Functions & Initial State ---
const API_URL = 'http://localhost:5000/api/auth';

const AuthContext = React.createContext();

const App = () => {
    const [page, setPage] = useState('login'); // 'login', 'register', 'forgot-password', 'reset-password', 'dashboard', 'admin'
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);

    const authContextValue = useMemo(() => ({
        user,
        setUser,
        login: async (email, password) => {
            try {
                const { data } = await axios.post(`${API_URL}/login`, { email, password });
                localStorage.setItem('authToken', data.token);
                localStorage.setItem('authRefreshToken', data.refreshToken);
                localStorage.setItem('user', JSON.stringify(data));
                setUser(data);
                setPage('dashboard');
                toast.success('Login successful!');
                return data;
            } catch (error) {
                const message = error.response?.data?.message || 'Invalid credentials';
                toast.error(message);
                throw new Error(message);
            }
        },
        register: async (username, email, password) => {
            try {
                const { data } = await axios.post(`${API_URL}/register`, { username, email, password });
                toast.success(data.message || 'Registration successful! Please check your email to verify.');
                setPage('login');
            } catch (error) {
                const message = error.response?.data?.message || 'Registration failed';
                toast.error(message);
                throw new Error(message);
            }
        },
        logout: () => {
            localStorage.removeItem('authToken');
            localStorage.removeItem('authRefreshToken');
            localStorage.removeItem('user');
            setUser(null);
            setPage('login');
            toast.info('You have been logged out.');
        },
    }), [user]);

    // --- Authentication Check on App Load ---
    useEffect(() => {
        const checkLoggedIn = () => {
            const token = localStorage.getItem('authToken');
            const storedUser = localStorage.getItem('user');
            if (token && storedUser) {
                setUser(JSON.parse(storedUser));
                setPage('dashboard');
            }
            setLoading(false);
        };
        checkLoggedIn();
    }, []);
    
    // --- Render Logic ---
    if (loading) {
        return <div className="min-h-screen bg-gray-900 flex items-center justify-center"><div className="text-white text-xl">Loading...</div></div>;
    }

    const renderPage = () => {
        const urlParams = new URLSearchParams(window.location.search);
        const resetTokenFromUrl = urlParams.get('token');
        const path = window.location.pathname;

        if (page === 'reset-password' || (path.startsWith('/reset-password') && resetTokenFromUrl)) {
             return <ResetPasswordPage token={resetTokenFromUrl} setPage={setPage} />;
        }
        
        if (!user) {
            switch (page) {
                case 'register':
                    return <RegisterPage setPage={setPage} />;
                case 'forgot-password':
                    return <ForgotPasswordPage setPage={setPage} />;
                default:
                    return <LoginPage setPage={setPage} />;
            }
        } else {
            switch (page) {
                case 'admin':
                    return <AdminPage user={user} />;
                default:
                    return <DashboardPage user={user} />;
            }
        }
    };
    
    return (
        <AuthContext.Provider value={authContextValue}>
            <div className="min-h-screen bg-gray-900 text-white font-sans">
                <Toaster richColors position="top-right" />
                <Navbar user={user} setPage={setPage} logout={authContextValue.logout} />
                <main className="container mx-auto px-4 py-8">
                    {renderPage()}
                </main>
            </div>
        </AuthContext.Provider>
    );
};

// --- Components ---
const Navbar = ({ user, setPage, logout }) => (
    <nav className="bg-gray-800 shadow-lg">
        <div className="container mx-auto px-4">
            <div className="flex justify-between items-center py-4">
                <div className="text-2xl font-bold text-teal-400 cursor-pointer" onClick={() => setPage(user ? 'dashboard' : 'login')}>SecureAuth</div>
                <div>
                    {user ? (
                        <>
                            <button onClick={() => setPage('dashboard')} className="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium">Dashboard</button>
                            {user.roles && user.roles.includes('admin') && (
                                <button onClick={() => setPage('admin')} className="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium">Admin</button>
                            )}
                            <button onClick={logout} className="ml-4 bg-teal-500 hover:bg-teal-600 text-white font-bold py-2 px-4 rounded-lg transition duration-300">Logout</button>
                        </>
                    ) : (
                        <>
                            <button onClick={() => setPage('login')} className="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium">Login</button>
                            <button onClick={() => setPage('register')} className="ml-4 bg-teal-500 hover:bg-teal-600 text-white font-bold py-2 px-4 rounded-lg transition duration-300">Register</button>
                        </>
                    )}
                </div>
            </div>
        </div>
    </nav>
);

const AuthFormContainer = ({ title, children }) => (
    <div className="flex items-center justify-center py-12">
        <div className="w-full max-w-md bg-gray-800 rounded-2xl shadow-2xl p-8 space-y-6 border border-gray-700">
            <h2 className="text-3xl font-bold text-center text-white">{title}</h2>
            {children}
        </div>
    </div>
);

const Input = (props) => (
    <input
        className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-teal-500 transition"
        {...props}
    />
);

const Button = ({ children, ...props }) => (
    <button
        className="w-full py-3 font-semibold text-white bg-teal-500 rounded-lg hover:bg-teal-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-800 focus:ring-teal-500 transition duration-300 disabled:opacity-50"
        {...props}
    >
        {children}
    </button>
);

// --- Pages ---
const LoginPage = ({ setPage }) => {
    const { login } = React.useContext(AuthContext);
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [loading, setLoading] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        try {
            await login(email, password);
        } catch (error) {
            // Toast is handled in context
        } finally {
            setLoading(false);
        }
    };

    return (
        <AuthFormContainer title="Login">
            <form onSubmit={handleSubmit} className="space-y-6">
                <Input type="email" placeholder="Email Address" value={email} onChange={(e) => setEmail(e.target.value)} required />
                <Input type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} required />
                <div className="text-right">
                    <button type="button" onClick={() => setPage('forgot-password')} className="text-sm text-teal-400 hover:underline">Forgot Password?</button>
                </div>
                <Button type="submit" disabled={loading}>{loading ? 'Signing in...' : 'Sign In'}</Button>
                <p className="text-center text-sm text-gray-400">
                    Don't have an account? <button type="button" onClick={() => setPage('register')} className="font-medium text-teal-400 hover:underline">Register</button>
                </p>
            </form>
        </AuthFormContainer>
    );
};

const RegisterPage = ({ setPage }) => {
    const { register } = React.useContext(AuthContext);
    const [username, setUsername] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [loading, setLoading] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        try {
            await register(username, email, password);
        } catch (error) {
            // Toast handled in context
        } finally {
            setLoading(false);
        }
    };

    return (
        <AuthFormContainer title="Create an Account">
            <form onSubmit={handleSubmit} className="space-y-6">
                <Input type="text" placeholder="Username" value={username} onChange={(e) => setUsername(e.target.value)} required />
                <Input type="email" placeholder="Email Address" value={email} onChange={(e) => setEmail(e.target.value)} required />
                <Input type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} required />
                <Button type="submit" disabled={loading}>{loading ? 'Creating Account...' : 'Create Account'}</Button>
                <p className="text-center text-sm text-gray-400">
                    Already have an account? <button type="button" onClick={() => setPage('login')} className="font-medium text-teal-400 hover:underline">Login</button>
                </p>
            </form>
        </AuthFormContainer>
    );
};

const ForgotPasswordPage = ({ setPage }) => {
    const [email, setEmail] = useState('');
    const [loading, setLoading] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        try {
            const { data } = await axios.post(`${API_URL}/forgot-password`, { email });
            toast.success(data.message);
        } catch (error) {
            toast.error(error.response?.data?.message || 'Failed to send reset link.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <AuthFormContainer title="Forgot Password">
            <p className="text-center text-gray-400 mb-4">Enter your email and we'll send you a link to reset your password.</p>
            <form onSubmit={handleSubmit} className="space-y-6">
                <Input type="email" placeholder="Email Address" value={email} onChange={(e) => setEmail(e.target.value)} required />
                <Button type="submit" disabled={loading}>{loading ? 'Sending...' : 'Send Reset Link'}</Button>
                <p className="text-center text-sm text-gray-400">
                    Remembered your password? <button type="button" onClick={() => setPage('login')} className="font-medium text-teal-400 hover:underline">Login</button>
                </p>
            </form>
        </AuthFormContainer>
    );
};

const ResetPasswordPage = ({ setPage, token }) => {
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [loading, setLoading] = useState(false);
    const [currentToken, setCurrentToken] = useState(token);

    // This effect handles URL parsing if the component is rendered directly via URL
    useEffect(() => {
        if (!currentToken) {
            const urlParams = new URLSearchParams(window.location.search);
            const tokenFromURL = urlParams.get('token');
             if(tokenFromURL) {
                setCurrentToken(tokenFromURL);
             }
        }
    }, [currentToken]);

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (password !== confirmPassword) {
            toast.error("Passwords do not match.");
            return;
        }
        if (!currentToken) {
            toast.error("Invalid or missing reset token.");
            return;
        }
        setLoading(true);
        try {
            const { data } = await axios.post(`${API_URL}/reset-password`, { resetToken: currentToken, password });
            toast.success(data.message);
            setPage('login');
        } catch (error) {
            toast.error(error.response?.data?.message || 'Failed to reset password.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <AuthFormContainer title="Reset Your Password">
            <form onSubmit={handleSubmit} className="space-y-6">
                <Input type="password" placeholder="New Password" value={password} onChange={(e) => setPassword(e.target.value)} required />
                <Input type="password" placeholder="Confirm New Password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} required />
                <Button type="submit" disabled={loading}>{loading ? 'Resetting...' : 'Reset Password'}</Button>
            </form>
        </AuthFormContainer>
    );
};


const DashboardPage = () => {
    const { user } = React.useContext(AuthContext);

    return (
        <div className="bg-gray-800 rounded-2xl shadow-2xl p-8 border border-gray-700">
            <h1 className="text-4xl font-bold text-white mb-4">Welcome, <span className="text-teal-400">{user.username}</span>!</h1>
            <p className="text-gray-300 text-lg">This is your protected dashboard. Only logged-in users can see this.</p>
            <div className="mt-6 border-t border-gray-700 pt-6">
                <h3 className="text-2xl font-semibold text-white">Your Details</h3>
                <ul className="mt-4 space-y-2 text-gray-400">
                    <li><strong>Email:</strong> {user.email}</li>
                    <li><strong>Roles:</strong> {user.roles.join(', ')}</li>
                </ul>
            </div>
        </div>
    );
};

const AdminPage = () => {
    const { user } = React.useContext(AuthContext);

    // This is a fallback, middleware should prevent non-admins from seeing this
    if (!user.roles.includes('admin')) {
        return (
            <div className="bg-red-900 border border-red-500 text-white p-6 rounded-lg">
                <h1 className="text-3xl font-bold">Access Denied</h1>
                <p>You do not have permission to view this page.</p>
            </div>
        )
    }

    return (
        <div className="bg-gray-800 rounded-2xl shadow-2xl p-8 border border-gray-700">
            <h1 className="text-4xl font-bold text-white mb-4">Admin Dashboard</h1>
            <p className="text-gray-300 text-lg">This is a restricted area. Only users with the 'admin' role can see this content.</p>
             <div className="mt-6 border-t border-gray-700 pt-6">
                <h3 className="text-2xl font-semibold text-white">Admin Information</h3>
                <p className="mt-4 text-gray-400">You have special privileges to manage the system.</p>
            </div>
        </div>
    );
};


// Intercepting API calls to handle token refresh
axios.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    if (error.response.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      const refreshToken = localStorage.getItem('authRefreshToken');
      if (refreshToken) {
        try {
          const { data } = await axios.post(`${API_URL}/refresh-token`, { refreshToken });
          localStorage.setItem('authToken', data.token);
          axios.defaults.headers.common['Authorization'] = `Bearer ${data.token}`;
          originalRequest.headers['Authorization'] = `Bearer ${data.token}`;
          return axios(originalRequest);
        } catch (refreshError) {
          // On refresh error, logout user
          localStorage.removeItem('authToken');
          localStorage.removeItem('authRefreshToken');
          localStorage.removeItem('user');
          window.location.href = '/login'; // Force reload to login
          return Promise.reject(refreshError);
        }
      }
    }
    return Promise.reject(error);
  }
);

axios.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('authToken');
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);


export default App;