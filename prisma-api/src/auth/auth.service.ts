import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma.service';

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService,
        private jwtService:JwtService) {}
    
    async findORcreate(data: any) // data is the user object from 42
    {
        // console.log("findORcreate");
        // console.log(data);

        const player = await this.prisma.player.findUnique
        ({
            where: { email: data.email },
        });
    
        if (!player)
        return this.prisma.player.create
        ({
            data :{
                nickname : data.nickname,
                firstName : data.firstName,
                lastName : data.lastName,
                avatar    : data.avatar,
                email: data.email,
            },
        });

        return player;
    }

    async findById(PlayerId: string) // data is the user object from 42
    {
        // console.log("findORcreate");
        // console.log(data);

        const player = await this.prisma.player.findUnique
        ({
            where: { id: PlayerId },
        });
        return player;
    }

    public async JwtAccessToken(playerId: string/*, isSecondFactorAuthenticated = false*/) : Promise<string> {
        
        // const payload = {
        //     playerId,
        //     isSecondFactorAuthenticated,
        // };
        return this.jwtService.sign(
            {
                playerId,
                // isSecondFactorAuthenticated,
            },
            {
                secret: process.env.JWT_SECRET, 
                expiresIn: process.env.JWTEXPIRATION
            }
        );   
    }
}

