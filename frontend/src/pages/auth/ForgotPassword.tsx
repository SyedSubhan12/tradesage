import { useState } from "react";
import { Link } from "react-router-dom";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/lib/authContext";

const ForgotPassword = () => {
  const [email, setEmail] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  
  const { forgotPassword } = useAuth();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    setIsLoading(true);
    try {
      // Call forgotPassword from auth context
      const success = await forgotPassword(email);
      
      if (success) {
        setSubmitted(true);
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen bg-black text-white">
      {/* Left side - Form */}
      <div className="flex-1 flex items-center justify-center p-8 relative z-10">
        <div className="w-full max-w-md bg-black/30 backdrop-blur-xl p-8 rounded-2xl border border-white/10 shadow-xl">
          <div className="space-y-6">
            <div className="space-y-2">
              <h1 className="text-3xl font-bold text-white">Forgot Password</h1>
              <p className="text-gray-400">
                Enter your email address and we'll send you a link to reset your password
              </p>
            </div>

            {!submitted ? (
              <form onSubmit={handleSubmit} className="space-y-6">
                <div className="space-y-2">
                  <label htmlFor="email" className="text-sm font-medium text-gray-300">
                    Email address
                  </label>
                  <Input
                    id="email"
                    type="email"
                    placeholder="Enter your email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    className="w-full bg-white/10 border-white/20 focus:border-plasma-purple text-white placeholder:text-gray-500"
                    disabled={isLoading}
                  />
                </div>

                <Button 
                  type="submit" 
                  className="w-full bg-plasma-purple hover:bg-plasma-purple/90 text-white font-medium"
                  disabled={isLoading}
                >
                  {isLoading ? "Processing..." : "Reset Password"}
                </Button>
              </form>
            ) : (
              <div className="p-4 bg-green-900/20 border border-green-500/30 rounded-md text-green-400">
                <p>
                  If an account exists with the email <strong>{email}</strong>,
                  you will receive password reset instructions.
                </p>
              </div>
            )}

            <div className="text-center mt-6">
              <p className="text-sm text-gray-400">
                Remember your password?{" "}
                <Link
                  to="/auth/login"
                  className="text-plasma-purple hover:text-plasma-purple/80 font-medium"
                >
                  Back to Login
                </Link>
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Right side - Image */}
      <div className="hidden lg:block flex-1">
        <div className="h-full w-full relative">
          <img
            src="/33396f1e-01c2-4a30-8cae-c2b6ab4680e3.jpg.png"
            alt="Bitcoin cryptocurrency"
            className="h-full w-full object-cover"
          />
          <div className="absolute inset-0 bg-gradient-to-r from-black/80 to-transparent"></div>
        </div>
      </div>

      {/* Background effects */}
      <div className="absolute top-0 left-0 w-full h-full overflow-hidden -z-10">
        <div className="absolute top-20 right-[20%] w-72 h-72 bg-plasma-purple/20 rounded-full filter blur-[80px]"></div>
        <div className="absolute bottom-20 left-[30%] w-72 h-72 bg-blue-500/20 rounded-full filter blur-[80px]"></div>
      </div>
    </div>
  );
};

export default ForgotPassword; 