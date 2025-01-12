package com.ead.payment.controllers;

import com.ead.payment.dtos.PaymentRequestDto;
import com.ead.payment.enums.PaymentControl;
import com.ead.payment.models.PaymentModel;
import com.ead.payment.models.UserModel;
import com.ead.payment.services.PaymentService;
import com.ead.payment.services.UserService;
import com.ead.payment.specifications.SpecificationTemplate;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Optional;
import java.util.UUID;

@RestController
@CrossOrigin(origins = "*", maxAge = 3600)
public class PaymentController {

    @Autowired
    UserService userService;

    @Autowired
    PaymentService paymentService;

    @PreAuthorize("hasAnyRole('USER')")
    @PostMapping("/users/{userId}/payments")
    @Operation(summary = "Solicitar pagamento", description = "Este endpoint permite que um usuário solicite um pagamento, com validação para garantir que um pagamento anterior não tenha sido solicitado ou efetuado.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "202", description = "Pagamento solicitado com sucesso"),
            @ApiResponse(responseCode = "404", description = "Usuário não encontrado"),
            @ApiResponse(responseCode = "409", description = "Já existe um pagamento solicitado ou efetuado"),
            @ApiResponse(responseCode = "403", description = "Acesso negado")
    })
    public ResponseEntity<Object> requestPayment(@PathVariable(value="userId") UUID userId,
                                                 @RequestBody @Valid PaymentRequestDto paymentRequestDto){
        Optional<UserModel> userModelOptional = userService.findById(userId);
        if(userModelOptional.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found.");
        }
        Optional<PaymentModel> paymentModelOptional = paymentService.findLastPaymentByUser(userModelOptional.get());
        if(paymentModelOptional.isPresent()){
            if(paymentModelOptional.get().getPaymentControl().equals(PaymentControl.REQUESTED)){
                return ResponseEntity.status(HttpStatus.CONFLICT).body("Payment already requested.");
            }
            if(paymentModelOptional.get().getPaymentControl().equals(PaymentControl.EFFECTED) &&
                    paymentModelOptional.get().getPaymentExpirationDate().isAfter(LocalDateTime.now(ZoneId.of("UTC")))){
                return ResponseEntity.status(HttpStatus.CONFLICT).body("Payment already made.");
            }
        }
        return ResponseEntity.status(HttpStatus.ACCEPTED)
                .body(paymentService.requestPayment(paymentRequestDto, userModelOptional.get()));
    }

    @PreAuthorize("hasAnyRole('USER')")
    @GetMapping("/users/{userId}/payments")
    @Operation(summary = "Listar todos os pagamentos de um usuário", description = "Retorna todos os pagamentos de um usuário específico com paginação.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Pagamentos encontrados com sucesso"),
            @ApiResponse(responseCode = "404", description = "Usuário não encontrado"),
            @ApiResponse(responseCode = "403", description = "Acesso negado")
    })
    public ResponseEntity<Page<PaymentModel>> getAllPayments(@PathVariable(value="userId") UUID userId,
                                                             SpecificationTemplate.PaymentSpec spec,
                                                             @PageableDefault(page = 0, size = 10, sort = "paymentId", direction = Sort.Direction.DESC) Pageable pageable){
        return ResponseEntity.status(HttpStatus.OK).body(paymentService.findAllByUser(SpecificationTemplate.paymentUserId(userId).and(spec), pageable));
    }

    @PreAuthorize("hasAnyRole('USER')")
    @GetMapping("/users/{userId}/payments/{paymentId}")
    @Operation(summary = "Obter um pagamento de um usuário", description = "Retorna os detalhes de um pagamento específico de um usuário.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Pagamento encontrado com sucesso"),
            @ApiResponse(responseCode = "404", description = "Pagamento não encontrado para este usuário"),
            @ApiResponse(responseCode = "403", description = "Acesso negado")
    })
    public ResponseEntity<Object> getOnePayment(@PathVariable(value="userId") UUID userId,
                                                @PathVariable(value="paymentId") UUID paymentId){
        Optional<PaymentModel> paymentModelOptional = paymentService.findPaymentByUser(userId, paymentId);
        if(paymentModelOptional.isEmpty()){
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Payment not found for this user.");
        }
        return ResponseEntity.status(HttpStatus.OK).body(paymentModelOptional.get());
    }


}
