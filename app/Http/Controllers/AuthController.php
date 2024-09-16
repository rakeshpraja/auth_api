<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Models\Otp;
use App\Models\TempUser;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Request;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Facades\JWTAuth;
use Mail;
use App\Mail\CustomEmail;
use App\Mail\UpdateProfileVerifyEmail;
use Carbon\Carbon;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\DB;

class AuthController extends Controller
{
   
    public function register()
    {
        try {
           
            $validator = Validator::make(request()->all(), [
                'name' => 'required|string|max:255',
                'email' => 'required|string|email|max:255|unique:users',
                'password' => 'required|string|min:8|confirmed',
            ]);

            if ($validator->fails()) {
                return response()->json(['errors' => $validator->errors()], 400);
            }

           
            $user = new User();
            $user->name = request()->name;
            $user->email = request()->email;
            $user->password = bcrypt(request()->password);
            $user->save();

            $details = [
                "token" => rand(11111, 99999),
                'user' => $user,
            ];

            Mail::to(request()->email)->send(new CustomEmail($details));

            Otp::create([
                'user_id' => $user->id,
                'token' => $details['token'],
            ]);

            return response()->json(['user' => $user], 201);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Something went wrong: ' . $e->getMessage()], 500);
        }
    }

   
    public function login()
    {
        try {
            $validator = Validator::make(request()->all(), [
                'email' => 'required|email',
                'password' => 'required|string|min:6',
            ]);

            if ($validator->fails()) {
                return response()->json(['errors' => $validator->errors()], 422);
            }

            if (! $token = auth()->attempt($validator->validated())) {
                return response()->json(['error' => 'Unauthorized'], 401);
            }

            return $this->createNewToken($token);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Something went wrong: ' . $e->getMessage()], 500);
        }
    }

   
    public function updateProfile()
    {
        try {
            $validator = Validator::make(request()->all(), [
                'name' => 'required|string|max:255',
                'email' => 'required|string|email|max:255',
                'phone_number' => 'required|numeric',
                'pdf_file' => 'required|mimes:pdf|max:5242880', // 5MB
                'image' => 'required|image|mimes:jpeg,png,jpg|max:5242880', // 5MB
            ]);

            if ($validator->fails()) {
                return response()->json(['errors' => $validator->errors()], 400);
            }

            $pdfFileName = null;
            $imageFileName = null;

            if (request()->hasFile('pdf_file')) {
                $pdfFile = request()->file('pdf_file');
                $pdfFileName = time() . '.' . $pdfFile->getClientOriginalExtension();
                $pdfFile->storeAs('pdfs', $pdfFileName, 'public');
            }

            if (request()->hasFile('image')) {
                $imageFile = request()->file('image');
                $imageFileName = time() . '.' . $imageFile->getClientOriginalExtension();
                $imageFile->storeAs('images', $imageFileName, 'public');
            }

            $user = User::where('email', request()->email)->first();

            if (!$user) {
                return response()->json(['message' => 'Not found data'], 200);
            }
            
            $temp_user = new TempUser();
            $temp_user->user_id = $user->id;
            $temp_user->name = request()->name;
            $temp_user->email = request()->email;
            $temp_user->phone_number = request()->phone_number;
            $temp_user->pdf_file = $pdfFileName;
            $temp_user->image = $imageFileName;
            $temp_user->save();

            $details = [
                'expires_at' => Carbon::now()->addMinutes(5),
                "otp" => rand(1111, 9999),
                "token" => rand(11111, 99999),
                'user' => $user,
            ];

            Otp::create([
                'user_id' => $user->id,
                'otp' => $details['otp'],
                'expires_at' => Carbon::now()->addMinutes(1),
            ]);

            Mail::to($user->email)->send(new UpdateProfileVerifyEmail($details));

            return response()->json(['message' => 'OTP sent successfully'], 200);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Something went wrong: ' . $e->getMessage()], 500);
        }
    }

  
    public function logout()
    {
        try {
            auth()->guard('api')->logout();
            return response()->json(['message' => 'User successfully signed out']);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Something went wrong: ' . $e->getMessage()], 500);
        }
    }

   
    protected function createNewToken($token)
    {
        try {
            return response()->json([
                'access_token' => $token,
                'token_type' => 'bearer',
                'expires_in' => auth()->factory()->getTTL() * 60,
                'user' => auth()->user(),
            ]);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Something went wrong: ' . $e->getMessage()], 500);
        }
    }

    
    public function verify($token)
    {
        try {
            $otp = Otp::where('token', $token)->first();
            if (!$otp) {
                return response()->json(['error' => 'Invalid token'], 400);
            }

            $user = User::find($otp->user_id);
            $user->email_verified_at = now();
            $user->save();

            $otp->delete();
            return response()->json(['success' => 'User verified successfully']);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Something went wrong: ' . $e->getMessage()], 500);
        }
    }

   
    public function verifyUpdateProfile()
    {
        try {
            $validator = Validator::make(request()->all(), [
                'otp' => 'required',
                'user_id' => 'required',
            ]);

            if ($validator->fails()) {
                return response()->json(['errors' => $validator->errors()], 400);
            }

            $user = User::find(request()->user_id);
            if (!$user) {
                return response()->json(['error' => 'User not found'], 404);
            }

            $otp = Otp::where('otp', request()->otp)
                ->where('user_id', request()->user_id)
                ->latest()
                ->first();

            if (!$otp) {
                return response()->json(['error' => 'Invalid OTP'], 400);
            }

            if (Carbon::now()->greaterThan($otp->expires_at)) {
                return response()->json(['error' => 'OTP has expired'], 400);
            }

            $temp_user = TempUser::where('user_id', $otp->user_id)->latest()->first();
            if (!$temp_user) {
                return response()->json(['error' => 'User record not found'], 400);
            }

            $user->name = $temp_user->name;
            $user->phone_number = $temp_user->phone_number;
            $user->pdf_file = $temp_user->pdf_file;
            $user->image = $temp_user->image;
            $user->save();

            Otp::where('user_id', request()->user_id)->delete();
            TempUser::where('user_id', request()->user_id)->delete();

            return response()->json(['success' => 'User profile updated successfully'], 200);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Something went wrong: ' . $e->getMessage()], 500);
        }
    }

    public function forgotPassword()
    {
        try {
           
            $validator = Validator::make(request()->all(), [
                'email' => 'required|string|email|max:255',
            ]);

            if ($validator->fails()) {
                return response()->json(['errors' => $validator->errors()], 400);
            }

            $user = User::where('email', request()->email)->first();
            if (!$user) {
                return response()->json(['message' => 'User not found'], 404);
            }

           
            $token = Hash::make($user);

            
            DB::table('password_resets')->insert([
                'email' => request()->email,
                'token' => $token,
                'created_at' => Carbon::now(),
            ]);

          
            Mail::send('mail.password_reset', ['token' => $token], function ($message) use ($user) {
                $message->to($user->email);
                $message->subject('Reset Password Request');
            });

            return response()->json(['message' => 'Reset password email sent.']);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Something went wrong: ' . $e->getMessage()], 500);
        }
    }

    public function resetPassword()
    {
        try {
           
            $validator = Validator::make(request()->all(), [
                'email' => 'required|email',
                'password' => 'required|min:6',
            ]);

            if ($validator->fails()) {
                return response()->json(['errors' => $validator->errors()], 400);
            }

            
            $passwordReset = DB::table('password_resets')
                ->where('email', request()->email)->latest()
                ->first();

            if (!$passwordReset) {
                return response()->json(['message' => 'Token not found'], 400);
            }

            if (request()->token != $passwordReset->token) {
                return response()->json(['message' => 'Invalid token'], 400);
            }

          
            $user = User::where('email', request()->email)->first();
            if (!$user) {
                return response()->json(['message' => 'User not found'], 404);
            }

            
            $user->password = Hash::make(request()->password);
            $user->save();

           
            DB::table('password_resets')->where('email', request()->email)->delete();

            return response()->json(['message' => 'Password reset successfully.']);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Something went wrong: ' . $e->getMessage()], 500);
        }
    }
}
