interface base {
  email: string;
  password: string;
}
export interface LoginDto extends base {}
export interface SignUpDto extends base {}

export interface TokenDto {
  access_token: string;
  refresh_token: string;
}
