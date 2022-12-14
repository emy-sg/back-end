"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.OauthStrategy = void 0;
const passport_42_1 = require("passport-42");
const passport_1 = require("@nestjs/passport");
const common_1 = require("@nestjs/common");
const auth_service_1 = require("./auth.service");
let OauthStrategy = class OauthStrategy extends (0, passport_1.PassportStrategy)(passport_42_1.Strategy, '42') {
    constructor(authService) {
        super({
            clientID: process.env.UID,
            clientSecret: process.env.SECRET,
            callbackURL: process.env.callback,
            profileFields: {
                'nickname': 'login',
                'firstName': 'first_name',
                'lastName': 'last_name',
                'avatar': 'image.link',
                'email': 'email',
            }
        });
        this.authService = authService;
    }
    async validate(accessToken, refreshToken, profile, cb) {
        if (!profile)
            throw new common_1.UnauthorizedException("User not found");
        return profile;
    }
};
OauthStrategy = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [auth_service_1.AuthService])
], OauthStrategy);
exports.OauthStrategy = OauthStrategy;
//# sourceMappingURL=42.strategy.js.map