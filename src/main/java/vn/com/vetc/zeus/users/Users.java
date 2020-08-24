package vn.com.vetc.zeus.users;

import lombok.*;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;


@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@ToString
@Entity
@Table(name = "USERS")
public class Users {

    public enum Status{ACTIVE, INACTIVE}

    @Id
    private Integer id;

    @Column
    private String username;

    @Column
    private String password;

    @Column
    private String status;

}
