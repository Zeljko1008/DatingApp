import { Component, OnInit } from '@angular/core';
import { AccountService } from '../_services/account.service';
import { Observable, of } from 'rxjs';
import { User } from '../_models/user';
import { Router } from '@angular/router';
import { ToastrService } from 'ngx-toastr';

@Component({
  selector: 'app-nav',
  templateUrl: './nav.component.html',
  styleUrls: ['./nav.component.css']
})
export class NavComponent implements OnInit
{
  model: any = {};

  constructor(public accuntService: AccountService, private router: Router, private toastr: ToastrService )
  {

  }

  ngOnInit(): void {
  }



  login(){
    this.accuntService.login(this.model).subscribe({
      next: _ => {
        this.router.navigateByUrl('/members');
        this.model = {};
      }
      })
  }
  logout(){
    this.accuntService.logout();
    this.router.navigateByUrl('/');

  }
}
