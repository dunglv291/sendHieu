package login.dto.request;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder

public class JwtRequest {
    private String username;
    private String password;
}
